import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
backend=default_backend()

def generateKey():       #Generate serialized public and private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=backend)
    public_key = private_key.public_key()
    pemprivate = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )
    pempublic = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pemprivate,pempublic
   # print("Alice")
   # print(pemprivate)
   # print(pempublic)
  


def aliceSendKey(bobKU,aliceKR,key,iv):      #Generate digital signature,key ciphertext,iv ciphertext
    BOBpublic_key_serealized=bobKU
    BOBpublic_key = serialization.load_pem_public_key(
    BOBpublic_key_serealized,
    backend=default_backend()
    )


    keyciphertext = BOBpublic_key.encrypt(
    key,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None)
    )

    ivciphertext= BOBpublic_key.encrypt(
    iv,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None)
    )

    ALICEprivatekeyserealise=aliceKR
    ALICEprivate_key = serialization.load_pem_private_key(
    ALICEprivatekeyserealise,
    password=None,
    backend=default_backend()
    )


    message = b"A message I want to sign"
    signature = ALICEprivate_key.sign(
    message,
    padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    return keyciphertext,ivciphertext,signature
    #print(keyciphertext)
    #print(ivciphertext)
    #print(signature)

def bobReceiveKey(bobKR,aliceKU,keyciphertext,ivciphertext,signature): #receive key and verify the sender
    BOBprivate_key_serealized=bobKR
    BOBprivate_key = serialization.load_pem_private_key(
    BOBprivate_key_serealized,
    password=None,
    backend=default_backend()
    )
    key = BOBprivate_key.decrypt(
    keyciphertext,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
    )


    iv = BOBprivate_key.decrypt(
    ivciphertext,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
    )


    ALICEpublic_key_serealized=aliceKU

    ALICEpublic_key = serialization.load_pem_public_key(
    ALICEpublic_key_serealized,
    backend=default_backend()
    )
    print(key)
    print(iv)
    checkmessage=b"A message I want to sign"
    ALICEpublic_key.verify(
    signature,
    checkmessage,
    padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    return key,iv

def encryption(key,message,iv):    #encryption function
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend).encryptor()
    return encryptor.update(message) + encryptor.finalize()
def decryption(key,cipher,iv):    #decryption function
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend).decryptor()
    return decryptor.update(cipher) + decryptor.finalize()

class User():      #to access private key,symmetric key,iv of bob and alice
    def __init__(self,public,private,iv,key):
        self.public=public
        self.private=private
        self.iv=iv
        self.key=key
    
    def assym_serialized(self):
        self.private,self.public=generateKey()
    
flaga=flagb=flag1=0
next=1
while next==1:                           #loop to perform various steps  
    print("1->Generate Alice's pair of public and private keys")
    print("2->Generate bob's pair of public and private keys")
    print("3->Send a symmetric key from alice to bob")
    print("4->Recieve the key")
    print("5->Send a message fromm alice")
    print("6->Send a message from bob")
    x=int(input("Enter your choice: "))
    if x==1:                            
        flaga=1                          
        alice=User(b'0',b'0',b'0',b'0')
        alice.assym_serialized()
        aliceKU=alice.public
        print('Alice')
        print(alice.private)
        print(aliceKU)
    elif x==2:
        flagb=1
        bob=User(b'0',b'0',b'0',b'0')
        bob.assym_serialized()
        bobKU=bob.public
        print('Bob')
        print(bob.private)
        print(bobKU)
    elif x==3:
        if flaga==1 and flagb==1:           #to check if public and private keys pf Bob and Alice have been generated
            alice.key=os.urandom(32)
            alice.iv=os.urandom(16)
            keycipher,ivcipher,signature=aliceSendKey(bobKU,alice.private,alice.key,alice.iv)
            print('Alice')
            print(alice.key)
            print(alice.iv)
            print(keycipher)
            print(ivcipher)
            print(signature)
            flag1=1
        elif flaga==1:
            print('Please produce Bob\'s private and public keys ')
        else:
            print('Please proce Alice\'s private and public key ')
    elif x==4:
        if flag1==1:                           #to ensure that symmetric key has been shared and signed for verification
            bob.key,bob.iv=bobReceiveKey(bob.private,alice.public,keycipher,ivcipher,signature)
            print(bob.key)
            print(bob.iv)
            flag2=1
        else:
            print('No key and iv generated ')
    elif x==5 or x==6:                          
        if flag2==1:                            #to ensure that symmetric key has been shared between bth clients and authentication is complete
            if x==5:
                message=input('Enter a message for Bob: ')
            else:
                message=input('Enter a message for Alice: ')
            if len(message)%16!=0:           #to check if length of message is a multiple of 16
                rem=len(message)%16
                rem=16-rem
                message=message+' '*rem
            message=bytes(message,'utf-8') 
            cipher=encryption(alice.key,message,alice.iv)
            decryptedmessage=decryption(alice.key,cipher,alice.iv)
            print("Original message: {}".format(message))
            print("Cipher text: {}".format(cipher))
            print("Message decrypted {}".format(decryptedmessage))
        else:
            print('Authentication not done ')
    else:
        print('Sorry, invalid input')
        break
    next=int(input("Enter 1 to continue, else 0: "))
