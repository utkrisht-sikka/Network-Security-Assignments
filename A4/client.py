import os
import socket
from rsa import *
import hashlib


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


def request( name, rollno, PR_user,publickey_ca,PU_server):
    client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    client.connect(("127.0.0.1",12345))

    # send name, rollno to the server
    request_msg = (name + "," + rollno)
    request_msg_hash = request_msg+','+hashlib.sha256(request_msg.encode()).hexdigest()
    encrypted_msg = RSA_encrypt_string(request_msg_hash,PU_server)
    client.sendall(encrypted_msg.encode())
    

    # receive the encrypted msg from server
    msg = client.recv(1024).decode()
    print("Received from Server:", msg)
    if((msg == "NAME AND ROLLNO NOT FOUND")or(msg=="INTEGRITY FAILURE")):
        return 
    
    encencmsg_size = client.recv(1024).decode()
    
    encmsg_size = int.from_bytes(RSA_decrypt_bytes(encencmsg_size, PR_user), byteorder='little')

    client.send(RSA_encrypt_string(("Received len: "+str(encmsg_size)),PU_server).encode())
    enc_msg = b""

    while (len(enc_msg)<encmsg_size):
        data = client.recv(1024)
        enc_msg+=data

    print("Final message size:", len(enc_msg))    
    

    # decrypt the msg
    msg4 = RSA_decrypt_bytes(enc_msg.decode(), PR_user)
    
    
    # request certificate of Director from CA
    Cert_dir = request_ca("Director")
    PU_dir = getkey_from_certificate(Cert_dir)
    print("\n\n")

    
    # authenticate Director
    s8 = int.from_bytes(msg4[-4:], byteorder='little')
    encryptedhash1 = msg4[-4-s8:-4]
    print(f"Director size of encryptedhash: {s8}")
    msg3 = msg4[:(-4-s8)]
    s6 = int.from_bytes(msg3[-8:-4], byteorder='little')
    s7 = int.from_bytes(msg3[-4:], byteorder='little')
    print("size of Director's name:", s6)
    print("size of time_str:", s7)
    hash1 = hashlib.sha256(msg3).hexdigest()
    print("Director computed hash:", hash1)
    print("Director received encryptedhash:", encryptedhash1.decode())
    
    found_hash1 = RSA_decrypt_string(encryptedhash1.decode(), PU_dir)
    print("found_hash1")
    print(found_hash1)
    print("Digital signature of Director matched ", hash1 == found_hash1)
    time_str = msg3[-8-s7:-8].decode()
    print(f"Director time of signing:", time_str)
    print("\n\n")


    # request certificate of Registrar from CA
    Cert_reg = request_ca("Registrar")
    PU_reg = getkey_from_certificate(Cert_reg)
    print("\n\n")

    # authenticate Registrar
    msg2 = msg3[:(-8-s6-s7)]
    s5 = int.from_bytes(msg2[-4:], byteorder='little')
    encryptedhash2 = msg2[-4-s5:-4]
    print(f"Registrar size of encryptedhash: {s5}")
    msg1 = msg2[:(-4-s5)]
    s3 = int.from_bytes(msg1[-8:-4], byteorder='little')
    s4 = int.from_bytes(msg1[-4:], byteorder='little')
    print("size of Registrar's name:", s3)
    print("size of time_str:", s4)
    hash2 = hashlib.sha256(msg1).hexdigest()
    print("Registrar computed hash:", hash2)
    print("Registrar received encryptedhash:", encryptedhash2.decode())
    found_hash2 = RSA_decrypt_string(encryptedhash2.decode(), PU_reg)
    print("found_hash2")
    print(found_hash2)
    print("Digital signature of Registrar matched ", hash2 == found_hash2)
    s3 = int.from_bytes(msg1[-8:-4], byteorder='little')
    s4 = int.from_bytes(msg1[-4:], byteorder='little') 
    time_str = msg1[-8-s4:-8].decode()
    print(f"Registrar time of signing:", time_str)    
    print("\n\n")
    
    msg0 = msg1[:-8-s3-s4]
    s1 = int.from_bytes(msg0[-8:-4], byteorder='little')
    s2 = int.from_bytes(msg0[-4:], byteorder='little')

    print("size of PDF1:", s1)
    print("size of PDF2:", s2)
    print("\n\n")
    
    
    PDF1 = msg0[:s1]
    PDF2 = msg0[s1:s1+s2]


    # save the PDFs 
    file_name = "recvd_degree.pdf"
    file = open(file_name, "wb")
    file.write(PDF1)
    file.close()

    file_name = "recvd_grades.pdf"
    file = open(file_name, "wb")
    file.write(PDF2)
    file.close()
     
    # close the connection
    client.close()
     
     

if __name__ == "__main__":
    publickey_ca = (5, 437)
    print("Keys for the 3 students")
    print(RSA_keygen(53, 59))
    print(RSA_keygen(61, 67))
    print(RSA_keygen(71, 73))
    print("\n\n")

    Cert_server = request_ca("Server")
    PU_server = getkey_from_certificate(Cert_server)
    request("Person1", "2019215", (2011, 3127),publickey_ca,PU_server)
    # request("Person2", "2019216", (2263, 4087),publickey_ca,PU_server)
    # request("Person3", "2019217", (2291, 5183),publickey_ca,PU_server)
    

   


