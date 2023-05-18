import client
import socket



if __name__ == "__main__":

  e, d, n = client.RSA_keygen(29, 31)
  ca_e, ca_n = 5, 437
  client1 = client.Client((e, n), (d, n), (ca_e, ca_n), "ID1")
  client1.get_publickey_ofclient("ID2")
  # be open for communication

  s = socket.socket()        
  port = 12345               
  s.bind(('', port))        
  s.listen(5)    
  print ("Client 1 listening...")           
  
  while True:
    c, addr = s.accept()    
    print ('Got connection from', addr)
    c.send(client1.send('hello1',"ID2").encode())
    client1.receive(c.recv(1024).decode())
    c.send(client1.send('hello2',"ID2").encode())
    client1.receive(c.recv(1024).decode())
    c.send(client1.send('hello3',"ID2").encode())
    client1.receive(c.recv(1024).decode())
    c.close()
    break