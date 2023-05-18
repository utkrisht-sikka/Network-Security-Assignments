from math import gcd

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
  # form a string with numbers separated by comma 
  # input: string, output: string

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
  # input: string, output: string

  decrypted_msg=""
  for i in msg.split(","):
      decrypted_msg += chr(RSA(int(i), pu))
  return decrypted_msg

def RSA_encrypt_bytes(msg, pk):

  # Encrypt each byte separately
  # in this way form a list of numbers, 1 for each byte.
  # form a string with numbers separated by comma 
  # input: bytes, output: string  
  encrypted_msg=""

  for ch in msg:

    encrypted_msg += str(RSA(ch, pk))
    encrypted_msg += ","
  encrypted_msg = encrypted_msg[:-1]
  return encrypted_msg

def RSA_decrypt_bytes(msg, pu):
  # remove commas and make a list of numbers
  # decrypt each number separately to get ASCII codes
  # convert each ASCII code to byte
  # input: string, output: bytes 
  decrypted_msg=b""
  for i in msg.split(","):
      decrypted_msg += (RSA(int(i), pu)).to_bytes(1,'little')
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