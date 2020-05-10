import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend=default_backend()

def encryption(key,message,iv):    #encryption function
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend).encryptor()
    return encryptor.update(message) + encryptor.finalize()
def decryption(key,cipher,iv):    #decryption function
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend).decryptor()
    return decryptor.update(cipher) + decryptor.finalize()

message=input('Enter a message: h')
if len(message)%16!=0:           #to check if length of message is a multiple of 16
    rem=len(message)%16
    rem=16-rem
    message=message+' '*rem
message=bytes(message,'utf-8')   #to convert string into bytes
key = os.urandom(32)             #to generate a random key
iv = os.urandom(16)              #to generate random initialization variable
cipher=encryption(key,message,iv)
decryptedmessage=decryption(key,cipher,iv)
print("Original message: {}".format(message))
print("Cipher text: {}".format(cipher))
print("Message decrypted {}".format(decryptedmessage))






