import socket
from rsa import *
from _thread import *
import time
import hashlib
import os
import fitz
import ntplib
from datetime import datetime
from time import ctime

class entity:
    def __init__(self, name, PR):
        self.name = name
        self.PR = PR

     
    def add_sign(self, msg0):
        time_str = gettime()
        s3 = len(self.name.encode())
        s4 = len(time_str.encode())
        print("size of " + self.name + "'s name:", s3)
        print("size of time_str:", s4)
        print(f"{self.name} time of signing:", time_str)
        print("\n\n")

        msg1 = msg0 + self.name.encode() + time_str.encode() + s3.to_bytes(4,'little') + s4.to_bytes(4,'little')
        return msg1

    def add_hash(self, msg1):
        # hash the doc and encrypt hash using PR of entity
        hash = hashlib.sha256(msg1).hexdigest()
        print(f"{self.name} sent hash: {hash}")
        encryptedhash = RSA_encrypt_string(hash, self.PR).encode()
        print(f"{self.name} sent encryptedhash: {encryptedhash}")
        
        s5 = len(encryptedhash)
        print(f"{self.name} size of encryptedhash: {s5}")
        print("\n\n")
        msg2 = msg1 + encryptedhash + s5.to_bytes(4,'little')
        return msg2

def gettime():
    ntpc=ntplib.NTPClient() 
    curtime = ntpc.request('uk.pool.ntp.org').tx_time
    
    time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(curtime))
    return time_str

def request_ca(id):
    client_socket = socket.socket()
    host = '127.0.0.1'
    port = 8765
    print('Waiting for connection response from CA')
    try:
        client_socket.connect((host, port))
    except socket.error as e:
        print(str(e))
    res = client_socket.recv(1024)
    print("Received from CA:", res.decode())

    client_socket.send(str.encode(id))
    res = client_socket.recv(1024).decode('utf-8')
    # print("got from server: ",res )
    client_socket.close()
    return res


def getkey_from_certificate(cert):
    ''' Client extracts public key of the other client from its certificate.
        Returns tuple of the form (e,n)
    '''
    decrypted_msg = RSA_decrypt_string(cert, publickey_ca)
    print("Getting key from certificate:")
    print(decrypted_msg)
    
    contents=decrypted_msg.split("::")
    key = contents[1]
    key = key.split(',')
    key[0]=int(key[0][1:])
    key[1]=int(key[1][:-1])
    return (key[0],key[1])


def add_watermark(filename,timestamp):
    doc = fitz.open(filename)# new or existing PDF
    page = doc[0]  # new or existing page via doc[n]
    p = fitz.Point(50, 72)  # start point of 1st line

    text = "IIIT DELHI ACADEMICS: "+timestamp
    font = fitz.Font("helv")  # choose a font with small caps
    tw = fitz.TextWriter(page.rect)
    tw.append((250,450), text, font=font,fontsize =20, small_caps=True)
    tw.write_text(page)
    new_name=filename[0:-4]+"_stamped.pdf"
    doc.save(new_name)
    return new_name

def handle_client(connection,server_pk):
    
    # verify that name and rollno are indeed present in DB
    msg = RSA_decrypt_string(connection.recv(1024).decode(), server_pk)
    print("Received:", msg)
    print("\n\n")

    name, rollno, hash_val = msg.split(",")
    if((name,rollno) not in DB):
        connection.sendall("NAME AND ROLLNO NOT FOUND".encode())
        connection.close()
        return 
    
    #checking if the message hasn't been tampered with
    if(hashlib.sha256((name+','+rollno).encode()).hexdigest()!=hash_val):
        connection.sendall("INTEGRITY FAILURE".encode())
        connection.close()
        return
    connection.sendall("SUCCESS".encode())

    #get PU of client
    Cert_client = request_ca(rollno)
    PU_client = getkey_from_certificate(Cert_client)

    # put date and time
    time_str = gettime()

    # obtain the PDFs & add watermark to each
    degree , grade = DB[(name,rollno)]
    file = open(add_watermark(degree,time_str),"rb")
    PDF1 = file.read()
    file.close()

    file = open(add_watermark(grade,time_str),"rb")
    PDF2 = file.read()
    file.close()

    # concatenate the two PDFs
    PDFs = PDF1 + PDF2
    s1 = len(PDF1)
    s2 = len(PDF2)
    print("size of PDF1:", s1)
    print("size of PDF2:", s2)

    msg0 = PDFs+s1.to_bytes(4,'little')+s2.to_bytes(4,'little')
    registrar = entity("Registrar", (5, 2021))
    msg1 = registrar.add_sign(msg0)
    msg2 = registrar.add_hash(msg1)
    

    director = entity("Director", (7, 1517))
    msg3 = director.add_sign(msg2)
    msg4 = director.add_hash(msg3)
    
    # encrypt for confidentiality
    print("PU_client:",  PU_client)
    enc_msg = RSA_encrypt_bytes(msg4, PU_client).encode()
    

    # send the final message to client
    encmsg_size = len(enc_msg)
    encencmsg_size = RSA_encrypt_bytes(encmsg_size.to_bytes(4,'little'), PU_client).encode()

    connection.sendall(encencmsg_size)
    print("Ack recvd: ",RSA_decrypt_string(connection.recv(1024).decode(),server_pk))
    print("Final message size:", encmsg_size)
    connection.sendall(enc_msg)
    

    # close the connection
    connection.close()
  
    


if __name__ == "__main__":
    
    # filling DB map
    publickey_ca = (5, 437)
    DB = {}
    DB[("Person1", "2019215")] = (os.path.join("db", "Person1_degree.pdf"), os.path.join("db", "Person1_grades.pdf"))
    DB[("Person2", "2019216")] = (os.path.join("db", "Person2_degree.pdf"), os.path.join("db", "Person2_grades.pdf"))
    DB[("Person3", "2019217")] = (os.path.join("db", "Person3_degree.pdf"), os.path.join("db", "Person3_grades.pdf"))
    server_pk = (3, 799)
    server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    host = '127.0.0.1'
    port = 12345
    try:
        server_socket.bind((host, port))
    except socket.error as e:
        print(str(e))
        exit()
    print('Socket is listening...')
    server_socket.listen(5)

    while True:
        Client, address = server_socket.accept()
        print('Connected to: ' + address[0] + ':' + str(address[1]))
        start_new_thread(handle_client, (Client,server_pk, ))
        time.sleep(10) 
        
    
   
     

     

    