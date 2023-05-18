from math import gcd
import itertools
from datetime import datetime
from dateutil.relativedelta import relativedelta
import socket

def RSA(M, key):
  ''' RSA algo. Call this function for encryption or decryption. In case of decryption , key should be (d,n) '''
  e, n = key
  base = M % n
  ans = 1
  while (e > 0):
    if((e%2) == 1):
      ans = ( ans * base) % n
    base = ( base * base) % n
    e = e >> 1

  return ans
def RSA_encrypt_string(msg, pk):
  # convert chars to bytes and then encrypt each byte separately
  # in this way form a list of numbers, 1 for each char.
  # form a string with numbers separated by  
  encrypted_msg=""
  for ch in msg:
    encrypted_msg += str(RSA(ord(ch), pk))
    encrypted_msg += ","
  encrypted_msg = encrypted_msg[:-1]
  return encrypted_msg

def RSA_decrypt_string(msg, pu):
  # remove commas and make a list of numbers
  # decrypt each number separately to get ASCII codes
  # convert each ASCII code to char
  
  decrypted_msg=""
  for i in msg.split(","):
      decrypted_msg += chr(RSA(int(i), pu))
  return decrypted_msg

def RSA_keygen(p,q):
  ''' this function is not asked to be coded. Will remove it later. But our keys needed n > 255 . So, we self create keys by putting (p,q), s.t. pq > 255, into this function.'''
  n = p*q
  phi = (p-1)*(q-1)
  for e in range(2, phi):
    if(gcd(e, phi) == 1):
      break
  for d in range(2, phi):
    if( ((e*d)%phi) == 1):
      break
  return e, d, n

class Client:
  def __init__(self, pu, pr, pu_CA, ID):
    ''' pu is of the format (e, n),  pr -> (d, n) '''
    self.publickey = pu
    self.privatekey = pr
    self.publickey_ca = pu_CA
    self.map_certificates = {}
    self.ID = ID

  def get_publickey_ofclient(self, c):
    ''' c is the client we want to communicate with, ca is the cert auth '''
    # x = ca.get_certificate(c)
    x = self.request_ca(c)
    self.map_certificates[c] = x
    k = self.getkey_from_certificate(x)
    print("Cert received ",RSA_decrypt_string(x,self.publickey_ca))

  def checkexpiry(self, ID):
    decrypted_msg = RSA_decrypt_string(self.map_certificates[ID], self.publickey_ca)
    contents=decrypted_msg.split("::")
    start = contents[2]
    dur = int(contents[3])
    date_object = datetime.strptime(start, "%d/%m/%Y %H:%M:%S")
    new_date = date_object+relativedelta(years=dur)
    cur_date = datetime.now()
    if(cur_date > new_date):
      return 1
    else:
      return 0


  def send(self, msg,dest_id):
    ''' encrypt message msg, by calling encrypt(), and send to client dst'''

    if(self.checkexpiry(dest_id)):
      print("get cert again!")
      self.get_publickey_ofclient(dest_id)
    encrypted_msg = RSA_encrypt_string(msg, self.getkey_from_certificate(self.map_certificates[dest_id]))
    print("Client {s1} Sent {s2}".format( s1=self.ID, s2=encrypted_msg ))
    return encrypted_msg

  def receive(self, msg):
    decrypted_msg = RSA_decrypt_string(msg, self.privatekey)
    print("Client {s1} Received {s2}".format( s1=self.ID, s2=decrypted_msg ))
    return decrypted_msg

  def request_ca(self, id):
    client_socket = socket.socket()
    host = '127.0.0.1'
    port = 8765
    print('Waiting for connection response')
    try:
        client_socket.connect((host, port))
    except socket.error as e:
        print(str(e))
    res = client_socket.recv(1024)
    client_socket.send(str.encode(id))
    res = client_socket.recv(1024).decode('utf-8')
    # print("got from server: ",res )
    client_socket.close()
    return res

  def getkey_from_certificate(self, cert):
    ''' Client extracts public key of the other client from its certificate.
        Returns tuple of the form (e,n)
    '''
    decrypted_msg = RSA_decrypt_string(cert,self.publickey_ca)
    contents=decrypted_msg.split("::")
    key = contents[1]
    key = key.split(',')
    key[0]=int(key[0][1:])
    key[1]=int(key[1][:-1])
    return (key[0],key[1])



