# coding=utf-8
import json, os, sys
import traceback
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol import KDF
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from getpass import getpass

class Crittografia():
    def __init__(self):
        self.__pubkey = None
        self.__passw = None
        self.__salt = None
        self.__crypted = None
    
    def GenerateKey(self, password:str):
        try:            
            key = RSA.generate(2048)
            self.__privkey = key.export_key(passphrase = password)
            self.__pubkey = key.publickey()
           
        except Exception as e:
            print(str(e))
            input()
         
    def ImportPubKey(self,key:bytes):
        self.__pubkey = RSA.import_key(key)

    def ImportPrivKey(self,key:bytes, password:str):
        self.__privkey = RSA.import_key(key,password)

    def Crypt(self,content:bytes):
        cipher = PKCS1_OAEP.new(self.__pubkey)
        sessionKey = get_random_bytes(16)
        encSessionKey = cipher.encrypt(sessionKey)

        ciphAes = AES.new(sessionKey,AES.MODE_EAX)
        self.__crypted, tag = ciphAes.encrypt_and_digest(content)

        self.__jsonKeys = ['nonce', 'cyphertext', 'tag', 'enckey']
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

    @property
    def PrivKey(self):
        return self.__privkey

class Certificato():
    def __init__(self):
        self.__pubCA = ECC.import_key("""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdqBTMZ+Mmv9mYlvXE410J8rpWfm/
vxl6y+pWhVFLPKNs++iyWCiuTP+Y3un7c4ACzfwn++aDG/Gf4yWI0S0WPg==
-----END PUBLIC KEY-----""")
    
    def GeneraCert(self, id:str, password:str):
        self.__key = ECC.generate(curve='P-256')
        prk_settings = {
            'format': 'PEM',
            'passphrase': password,
            'protection': 'scryptAndAES256-CBC'
            }
        self.__privkey = self.__key.export_key(**prk_settings)
        self.__pubkey = self.__key.public_key()
        self.Serialize(id)     
    
    def ImportKey(self, keyIn:str, type:str, psw=None):
        if type == "pub":
            self.__pubkey = ECC.import_key(keyIn)
        elif type == "priv":
            self.__privkey = ECC.import_key(keyIn,psw)

    def VerificaFirma(self, content:bytes, pubkey, sign):
        try:
            h = SHA256.new(content)
            verifier = DSS.new(pubkey,'deterministic-rfc6979')
            verifier.verify(h, b64decode(sign))
            return True
        except ValueError:
            print("FIRMA NON VALIDA")
            return False
        
    def ImportCert(self,certraw, privkey_raw, psw:str):
        cert = self.Deserialize(certraw)
        if self.VerificaFirma(certraw,self.__pubCA,cert['sig']):
            print("OK")
            try:
                self.ImportKey(privkey_raw,'priv',psw)
                self.ImportKey(cert['pubk'],'pub')
            except:
                print("ERRORE IMPORTAZIONE CHIAVI")
        else:
            print("SI E' ROTTO")


    def Firma(self, content:bytes):
        h = SHA256.new(content)
        signer = DSS.new(self.__privkey,'deterministic-rfc6979')
        signed = signer.sign(h)

        self.__sign = b64encode(signed).decode('utf-8')
                
    
    def Serialize(self, id:str):
        pubk_str = self.__pubkey.export_key(format='PEM')
        #print(pubk_str)
        tmp = {'id': id, 'pubk':pubk_str,'sig':''}
        self.__resJSON = json.dumps(tmp).encode('utf-8')

    def Deserialize(self,content:str):
        return json.loads(content)

    @property
    def resJSON(self):
        return self.__resJSON

    @property
    def Privkey(self):
        return self.__privkey
    
    @property
    def CA_Pubkey(self):
        return self.__pubCA

# Definizione funzione "clear terminal" #
def clear():
    if os.name == 'nt':
        return os.system('cls')
    else:
        return os.system('clear')

# Operazioni su File #
def saveFile(path:str, content:bytes):
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



def ImportKeyCert(cert:Certificato):
    clear()
    print("CERTIFICATO ESISTENTE")
    path = showPrompt("path")
    rawfile = readFile(path)
    print("CHIAVE PRIVATA")
    path = showPrompt("path")
    psw = getpass("Inserisci la password per la chiave privata: ")
    privkey_raw = readFile(path)
    
    try:
        cert.ImportCert(rawfile,privkey_raw,psw)
        input("\nPremi INVIO per continuare")

    except Exception as e:
        print("ERRORE DI IMPORTAZIONE")
        print(str(e))
        input()
    clear()

while True:
    cert = Certificato()
    clear()
    tmp = showPrompt("init")
    if tmp == 1:
        try:
            # Scelta utilizzo certificato #
            newCert = input("Generare un certificato? S/N ")
            if newCert.upper() == "S": 
                psw = showPrompt("password")
                cert.GeneraCert('micheleschelfi',psw)                
                print("GENERAZIONE CERTIFICATO...")
                clear()
                print("CERTIFICATO GENERATO")
                path = showPrompt("path")
                print("\nFile salvato in: ["+saveFile(path+".cert",cert.resJSON)+"]")
                print("\nChiave privata salvata in: ["+saveFile("key.priv",cert.Privkey.encode('utf-8'))+"]")
            elif newCert.upper() == "N": 
                ImportKeyCert(cert)
            else:
                print("Parametro non valido")
                continue
            # File "bersaglio" #
           
        except Exception as e:
            tb = traceback.format_exc()
            print(tb) # SOLO PER DEBUG
            input("\nPremi INVIO per continuare")
    elif tmp == 2:
        ImportKeyCert(cert)
        print("TODO")
    elif tmp == 3:
        break
    else:
        print("Parametro non valido")
        input("\nPremi INVIO per continuare")