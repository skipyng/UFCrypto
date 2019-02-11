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
    
    def Password(self, psw:str, saltIn:bytes = get_random_bytes(16)):
        self.__salt = saltIn
        self.__passw = KDF.scrypt(psw,self.__salt,32,16384,8,1)

    def GenerateKey(self):
        try:            
            key = RSA.generate(2048)
            self.__privkey = key.export_key("DER")
            self.__pubkey = key.publickey()
            self.EncryptPrivKey()
        except Exception as e:
            print(str(e))
            input()
         
    def EncryptPrivKey(self):
        cipher = AES.new(self.__passw, AES.MODE_CCM)
        encKey, tag = cipher.encrypt_and_digest(self.__privkey)
        self.__jsonKeys = ['nonce', 'ciphertext', 'tag','salt']
        self.__jsonVal = [cipher.nonce, encKey, tag, self.__salt]

    def DecryptPrivKey(self,inputObj:dict):
        cipher = AES.new(self.__passw, AES.MODE_CCM, nonce=b64decode(inputObj['nonce']))
        self.__privkey = cipher.decrypt_and_verify(b64decode(inputObj['ciphertext']), b64decode(inputObj['tag']))

    def ImportPubKey(self,key:bytes):
        self.__pubkey = RSA.import_key(key)

    def Crypt(self,content:bytes):
        cipher = PKCS1_OAEP.new(self.__pubkey)
        self.__crypted = cipher.encrypt(content)

    def Decrypt(self,content:bytes):
        tmp = RSA.import_key(self.__privkey)
        cipher = PKCS1_OAEP.new(tmp)
        return cipher.decrypt(content)

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
    
    @property
    def Crypted(self):
        return self.__crypted


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
                # Generazione chiavi crittografando la privata con una password #
                obj.Password(psw)
                print("Generazione chiavi in corso...")
                obj.GenerateKey()
                clear()
                print("\n CHIAVE GENERATA")
                path = showPrompt("path")
                # Salvataggio chiavi pubbliche e private #
                print("\nChiave pubblica salvata in: ["+saveFile(path+".pub",obj.PubKey.export_key("DER"))+"]")
                print("\nChiave privata salvata in: ["+saveFile(path+".priv",obj.resJSON)+"]")
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
            print("\nFile salvato in: ["+saveFile(path+".crypt",obj.Crypted)+"]")
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
            tmp = obj.deserialize(readFile(path))
            obj.Password(psw,b64decode(tmp['salt']))
            obj.DecryptPrivKey(tmp)
            print("CHIAVE PRIVATA IMPORTATA")
            print("\n FILE CRIPTATO")
            path=showPrompt("path")
            tmp = obj.Decrypt(readFile(path))
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