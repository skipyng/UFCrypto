# coding=utf-8
import json, os, sys
import traceback
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol import KDF
from Crypto.Random import get_random_bytes
from getpass import getpass

class Certificato():
    def __init__(self):
        self.__pubCA = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdqBTMZ+Mmv9mYlvXE410J8rpWfm/
vxl6y+pWhVFLPKNs++iyWCiuTP+Y3un7c4ACzfwn++aDG/Gf4yWI0S0WPg==
-----END PUBLIC KEY-----"""
    
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

    def VerificaFirma(self):
        pass

    def Firma(self):
        pass
    
    def Serialize(self, id:str):
        pubk_str = self.__pubkey.export_key(format='PEM')
        print(pubk_str)
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

while True:
    cert = Certificato()
    clear()
    tmp = showPrompt("init")
    if tmp == 1:
        try:
            # Scelta utilizzo certificato #
            importPub = input("Generare un certificato? S/N ")
            if importPub.upper() == "S": 
                psw = showPrompt("password")
                cert.GeneraCert('micheleschelfi',psw)                
                print("GENERAZIONE CERTIFICATO...")
                clear()
                print("CERTIFICATO GENERATO")
                path = showPrompt("path")
                print("\nFile salvato in: ["+saveFile(path+".cert",cert.resJSON)+"]")
                print("\nChiave privata salvata in: ["+saveFile("key.priv",cert.Privkey.encode('utf-8'))+"]")
            elif importPub.upper() == "N": 
                clear()
                print("CERTIFICATO ESISTENTE")
                path = showPrompt("path")
                clear()
            else:
                print("Parametro non valido")
                continue
            # File "bersaglio" #
           
        except Exception as e:
            tb = traceback.format_exc()
            print(tb) # SOLO PER DEBUG
            input("\nPremi INVIO per continuare")
    elif tmp == 2:
        try:
            clear()
            print("\nCHIAVE PRIVATA")
            path = showPrompt("path")
            psw = getpass("Inserisci la password per la chiave privata: ")
            cert.ImportKey(readFile(path),'priv',psw)
            
        except Exception as e:
            tb = traceback.format_exc()
            if str(e) == "MAC check failed":
                print("Errore di crittografia. Parametri non validi")
            else:
                print(tb) # SOLO PER DEBUG
            input("\nPremi INVIO per continuare")
    elif tmp == 3:
        break
    else:
        print("Parametro non valido")
        input("\nPremi INVIO per continuare")