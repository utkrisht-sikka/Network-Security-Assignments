import client
import socket


if __name__ == "__main__":

  e, d, n = client.RSA_keygen(37,41)
  ca_e, ca_n = 5, 437
  client2 = client.Client((e, n), (d, n), (ca_e, ca_n), "ID2")
  client2.get_publickey_ofclient("ID1")
  
  #communicate

  s = socket.socket()        
  port = 12345               
  s.connect(('127.0.0.1', port))
  client2.receive(s.recv(1024).decode())
  s.send(client2.send('ack1',"ID1").encode())
  client2.receive(s.recv(1024).decode())
  s.send(client2.send('ack2',"ID1").encode())
  client2.receive(s.recv(1024).decode())
  s.send(client2.send('ack3',"ID1").encode())
  s.close()    