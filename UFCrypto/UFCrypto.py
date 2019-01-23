import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class Crittografia:
    def __init__(self,keyBytes:int,authentication:bool):
        self.__key:int = generateKey(keyBytes)
        self.__auth:bool = authentication

    @property
    def key(self):
        return self.__key

    @property
    def cipher(self):
        return self.__cipher
     
    def generateKey(bytes):
        return get_random_bytes(bytes)

    def generateCipher():
        if self.__auth:

