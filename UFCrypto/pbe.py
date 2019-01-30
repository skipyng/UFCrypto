# coding=utf-8
import json, os, sys
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol import KDF
from getpass import getpass


class Crittografia:
    def __init__(self):
        self.__key = None
        self.__salt = None

    # Generazione chiave da password e eventuale SALT #
    def Password(self, psw:str, saltIn:bytes = get_random_bytes(16)):
        self.__salt = saltIn
        self.__key = KDF.scrypt(psw,self.__salt,32,16384,8,1)

    def crypt(self, plaintext:str):
        # Crittografia in modalità CON AUTENTICAZIONE #
        if self.__auth:  
            cipher = AES.new(self.__key, AES.MODE_CCM)
            self.__ciphertext, tag = cipher.encrypt_and_digest(bytes(plaintext, 'utf-8'))
            self.__jsonKeys = ['nonce', 'ciphertext', 'tag','salt']
            self.__jsonVal = [cipher.nonce, self.__ciphertext, tag,self.__salt]

        # Crittografia in modalità SENZA AUTENTICAZIONE #
        else:
            cipher = AES.new(self.__key, AES.MODE_CBC)
            self.__ciphertext = cipher.encrypt(pad(bytes(plaintext, 'utf-8'), AES.block_size))
            self.__jsonKeys = ['iv', 'ciphertext','salt']
            self.__jsonVal = [cipher.iv, self.__ciphertext,self.__salt]

    def decrypt(self, inputObj:dict):
        # Decrittazione CON AUTENTICAZIONE #
        if self.__auth:
            cipher = AES.new(self.__key, AES.MODE_CCM, nonce=b64decode(inputObj['nonce']))
            self.__plaintext = str(cipher.decrypt_and_verify(b64decode(inputObj['ciphertext']), b64decode(inputObj['tag'])), 'utf-8')
        # Decrittazione SENZA AUTENTICAZIONE #
        else:
            cipher = AES.new(self.__key, AES.MODE_CBC, b64decode(inputObj['iv']))
            self.__plaintext = str(unpad(cipher.decrypt(b64decode(inputObj['ciphertext'])), AES.block_size), 'utf-8')
    
    # Popolamento oggetto JSON #
    def serialize(self):
        json_values = [b64encode(x).decode('utf-8') for x in self.__jsonVal]
        return json.dumps(dict(zip(self.__jsonKeys, json_values)))

    # Controllo se file salvato è stato fatto CON o SENZA autenticazone #
    # Controllo effettuato tramite numero di valori salvati #
    def deserialize(self, input:str):
        tmp = json.loads(input)
        self.__auth = len(tmp) > 3
        return tmp

    # Proprietà classe #
    @property
    def key(self):
        return self.__key

    @key.setter
    def key(self, value:str):
        self.__key = bytes(value, 'utf-8')

    @property
    def ciphertext(self):
        return self.__ciphertext

    @property
    def auth(self):
        return self.__auth

    @auth.setter
    def auth(self, value:bool):
        self.__auth = value

    @property
    def resJSON(self):
        return self.serialize()

    @property
    def plaintext(self):
        return self.__plaintext
      

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

        elif type == "crypt":
            return int(input("""
            Seleziona in che modo criptare:
                1 - Con autenticazione
                2 - Senza autenticazione
                \n> """))
        elif type == "path":
            return input("\tInserisci il percorso/nome del file \n\n\tPercorso corrente: \n\t[" + os.getcwd() + "]\n>")
        elif type == "password":
            return getpass("Inserisci la password: ")
    except:
        print("Parametro non valido")
        showPrompt(type)

#########################################

# Operazioni su File #
def saveFile(path:str, content:str):
    with open(path, "w") as f:
        f.write(content)
        
def readFile(path:str):
    with open(path, "r") as f:
        return f.read()

# Definizione funzione "clear terminal" #
def clear():
    if os.name == 'nt':
        return os.system('cls')
    else:
        return os.system('clear')

# MAIN #
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
        tmp2 = showPrompt("crypt")
        clear()
        # Scelta modalità (con o senza autenticazione) #
        if tmp2 == 1:
            obj.auth = True
        elif tmp2 == 2:
            obj.auth = False
        # Cifratura #
        obj.crypt(input("Testo da cifrare: "))
        clear()
        # Salvataggio #
        print("\n\t------------ CIFRATO ------------ ")
        path = showPrompt("path")
        saveFile(path, obj.resJSON)
        print("File criptato generato in: [" + os.getcwd() + "\\" + path + "]")
        input("Premi INVIO per continuare")
    elif tmp == 2:
        clear()
        print("\n\t------------ PASSWORD ------------ ")
        psw = showPrompt("password")
        clear()
        print("\n\t------------ CIFRATO ------------ ")
        try:
            tmp = obj.deserialize(readFile(showPrompt("path")))
            # Rigenerazione chiave partendo da SALT salvato #
            obj.Password(psw,b64decode(tmp['salt']))
            # Decrittazione #
            obj.decrypt(tmp)
            print("\nTesto decriptato: " + obj.plaintext)
            input("\nPremi INVIO per continuare")
        except Exception as e:
            if str(e) == "MAC check failed":
                print("Password errata")
            else:
                print(str(e))
            input("\nPremi INVIO per continuare")
    elif tmp == 3:
        break
    else:
        print("Parametro non valido")
        input("\nPremi INVIO per continuare")
