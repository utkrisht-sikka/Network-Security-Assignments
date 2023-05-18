import socket
import os
from _thread import *

from math import gcd
import itertools
from datetime import datetime
from dateutil.relativedelta import relativedelta


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

class CA:
  id_iter = itertools.count()

  def __init__(self, pu, pr):
    self.map_pukeys = {}
    self.privatekey = pr
    self.id = next(self.id_iter)
  
  def get_certificate(self, client):
    ''' returns encrypted certificate which has PU of client'''

    # (IDA, PUA, TA, DURA, IDCA)
    # DURA is in years
    PUA = self.map_pukeys[client]
    TA = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    # TA = str(datetime.date(1970,1,1)) 
    DURA = 5
    cert_contents = [client, PUA,TA,DURA, self.id]
    msg=""
    for c in cert_contents:
      msg+="::"+str(c)
    msg=msg[2:]
    enc_msg=RSA_encrypt_string(str(msg),self.privatekey)
    return enc_msg

  def add_publickey(self, id_client, key):
    self.map_pukeys[id_client] = key 

  def handle_client(self, connection):
      connection.send(str.encode('Server is working:'))
      data = connection.recv(2048)
      m = data.decode('utf-8')
      print("Server received: ",m)
      response = self.get_certificate(m)
      print("sending response: ", response)
      connection.sendall(str.encode(response))
      connection.close()



if __name__ == "__main__":

  ca_e, ca_d, ca_n = RSA_keygen(19, 23)
  CA_obj = CA((ca_e, ca_n), (ca_d, ca_n)) # keys were self created. We chose p,q ensuring n > 255
  e1, n1 = 11, 899
  CA_obj.add_publickey("ID1", (e1, n1))
  e2, n2 = 7, 1517
  CA_obj.add_publickey("ID2", (e2, n2))



  server_socket = socket.socket()
  host = '127.0.0.1'
  port = 8765
  ThreadCount = 0
  try:
      server_socket.bind((host, port))
  except socket.error as e:
      print(str(e))
  print('Socket is listening..')
  server_socket.listen(5)


  while True:
      Client, address = server_socket.accept()
      print('Connected to: ' + address[0] + ':' + str(address[1]))
      start_new_thread(CA_obj.handle_client, (Client, ))
      
      
  server_socket.close()