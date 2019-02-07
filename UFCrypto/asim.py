# coding=utf-8
import json, os, sys
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from Crypto.Random import get_random_bytes
from getpass import getpass

class Crittografia:
    def __init__(self):
        self.__passw = None
        self.__salt = None
    
    def Password(self, psw:str, saltIn:bytes = get_random_bytes(16)):
        self.__salt = saltIn
        self.__passw = KDF.scrypt(psw,self.__salt,32,16384,8,1)

    def GenerateKey(self):
        key = RSA.generate(2048)
        self.__privkey = key.export_key("DER")
        self.__pubkey = key.publickey().export_key("DER")
        self.EncryptPrivKey()
         
    def EncryptPrivKey(self):
        cipher = AES.new(self.__passw, AES.MODE_CCM)
        self.__ciphertext, tag = cipher.encrypt_and_digest(self.__privkey)
        self.__jsonKeys = ['nonce', 'ciphertext', 'tag','salt']
        self.__jsonVal = [cipher.nonce, self.__ciphertext, tag, self.__salt]

    def serialize(self):
        json_values = [b64encode(x).decode('utf-8') for x in self.__jsonVal]
        return json.dumps(dict(zip(self.__jsonKeys, json_values)))




    @property
    def resJSON(self):
        return self.serialize()
    @property
    def PubKey(self):
        return self.__pubkey
    @property
    def PrivKey(self):
        return self.__privkey


# Definizione funzione "clear terminal" #
def clear():
    if os.name == 'nt':
        return os.system('cls')
    else:
        return os.system('clear')

# Operazioni su File #
def saveFile(path:str, content:str):
    with open(path, "wb") as f:
        f.write(content)
        return os.path.realpath(f.name)

def readFile(path:str):
    with open(path, "rb") as f:
        return f.read()

# Messaggi "prompt" per l'utente #
def showPrompt(type:str):
    try:
        if type == "init":
            return int(input("""
            Seleziona l'attività:
                1 - Cripta
                2 - Decripta
                3 - Chiudi
                \n> """))

        elif type == "path":
            return input("\tInserisci il percorso/nome del file \n\n\tPercorso corrente: \n\t[" + os.getcwd() + "]\n>")
        elif type == "password":
            return getpass("Inserisci la password: ")
    except:
        print("Parametro non valido")
        showPrompt(type)

##############################################

while True:
    obj = Crittografia()
    clear()
    tmp = showPrompt("init")
    if tmp == 1:
        clear()
        print("\n\t------------ PASSWORD ------------ ")
        psw = showPrompt("password")
        clear()
        # Generazione chiave con SALT casuale #
        obj.Password(psw)
        obj.GenerateKey()
        clear()
        print("\n CHIAVE GENERATA")
        path = showPrompt("path")
        print("\n Chiave pubblica salvata in: ["+saveFile(path+".pub",obj.PubKey)+"]")
        print("\n Chiave privata salvata in: ["+saveFile(path+".pub",obj.resJSON)+"]")