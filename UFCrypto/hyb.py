# coding=utf-8
import json, os, sys
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol import KDF
from Crypto.Random import get_random_bytes
from getpass import getpass

class Crittografia(object):
    def __init__(self):
        self.__pubkey = None
        self.__passw = None
        self.__salt = None
        self.__crypted = None
    
    def GenerateKey(self, password:str):
        try:            
            key = RSA.generate(2048)
            self.__privkey = key.export_key(passphrase = password,)
            self.__pubkey = key.publickey()
           
        except Exception as e:
            print(str(e))
            input()
         
    def ImportPubKey(self,key:bytes):
        self.__pubkey = RSA.import_key(key)

    def ImportPrivKey(self,key:bytes,password):
        self.__privkey = RSA.import_key(key,password)

    def Crypt(self,content:bytes):
        cipher = PKCS1_OAEP.new(self.__pubkey)
        sessionKey = get_random_bytes(16)
        encSessionKey = cipher.encrypt(sessionKey)

        ciphAes = AES.new(sessionKey,AES.MODE_EAX)
        self.__crypted, tag = ciphAes.encrypt_and_digest(content)

        self.__jsonKeys = ['nonce', 'ciphertext', 'tag', 'enckey']
        self.__jsonVal = [ciphAes.nonce, self.__crypted, tag, encSessionKey]

    def Decrypt(self,dictIn:dict):
        cipher = PKCS1_OAEP.new(self.__privkey)
        sessionkey = cipher.decrypt(b64decode(dictIn['enckey']))

        ciphAes = AES.new(sessionkey,AES.MODE_EAX, nonce = b64decode(dictIn['nonce']))
        return ciphAes.decrypt_and_verify(b64decode(dictIn['cyphertext']), b64decode(dictIn['tag']))

    def serialize(self):
        json_values = [b64encode(x).decode('utf-8') for x in self.__jsonVal]
        return bytes(json.dumps(dict(zip(self.__jsonKeys, json_values))),'utf-8')

    def deserialize(self, input:str):
        return json.loads(input)

    @property
    def resJSON(self):
        return self.serialize()

    @property
    def PubKey(self):
        return self.__pubkey

    @PubKey.setter
    def PubKey(self,value:bytes):
        self.__pubkey = value
    
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
        try:
            # Scelta utilizzo chiavi #
            importPub = input("Importare una chiave pubblica? S/N ")
            if importPub.upper() == "S": 
                path = showPrompt("path")
                obj.ImportPubKey(readFile(path))
                print("CHIAVE IMPORTATA")
            elif importPub.upper() == "N": 
                clear()
                print("GENERAZIONE COPPIA DI CHIAVI\n")
                print("\n\t------------ PASSWORD ------------ ")
                psw = showPrompt("password")
                clear()
                print("Generazione chiavi in corso...")
                obj.GenerateKey(psw)
                clear()
                print("\n CHIAVE GENERATA")
                path = showPrompt("path")
                # Salvataggio chiavi pubbliche e private #
                print("\nChiave pubblica salvata in: ["+saveFile(path+".pub",obj.PubKey.export_key())+"]")
                print("\nChiave privata salvata in: ["+saveFile(path+".priv",obj.PrivKey)+"]")
                input("\nPremi INVIO per continuare")
                clear()
            else:
                print("Parametro non valido")
                continue
            # File "bersaglio" #
            print("FILE DA CRIPTARE")
            path = showPrompt("path")
            print("Crittazione in corso...")
            obj.Crypt(readFile(path))
            print("File criptato.")
            print("\nFile salvato in: ["+saveFile(path+".crypt",obj.resJSON)+"]")
            input("\nPremi INVIO per continuare")
        except Exception as e:
            print(str(e))
            input("\nPremi INVIO per continuare")
    elif tmp == 2:
        try:
            clear()
            print("\nCHIAVE PRIVATA")
            path = showPrompt("path")
            psw = getpass("Inserisci la password per la chiave privata: ")
            obj.ImportPrivKey(readFile(path),psw)
            print("\n FILE CRIPTATO")
            path = showPrompt("path")
            tmp = obj.Decrypt(json.loads(readFile(path)))
            clear()
            print("FILE DECRITTATO")
            path = showPrompt("path")
            print("\nFile decrittato salvato in: ["+saveFile(path,tmp)+"]")
            input("\nPremi INVIO per continuare")
        except Exception as e:
            if str(e) == "MAC check failed":
                print("Errore di crittografia. Parametri non validi")
            else:
                print(str(e))
            input("\nPremi INVIO per continuare")
    elif tmp == 3:
        break
    else:
        print("Parametro non valido")
        input("\nPremi INVIO per continuare")