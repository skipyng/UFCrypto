# coding=utf-8
import json
import os
import sys
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class Crittografia:
    def __init__(self):
        self.__key = None
        pass

    def newKey(self, leng):
        # Gestione eccezione lunghezza chiave (multiplo di 16) #
        if leng % 16 == 0:
            self.__key = get_random_bytes(len)
        else:
            print("Errore nella generazione della chiave. Input non valido")
            self.__key = None

    def crypt(self, plaintext):
        if self.__auth:  # Crittografia in modalità CON AUTENTICAZIONE #
            cipher = AES.new(self.__key, AES.MODE_CCM)
            self.__ciphertext, tag = cipher.encrypt_and_digest(
                bytes(plaintext, 'utf-8'))
            self.__jsonKeys = ['nonce', 'ciphertext', 'tag']
            self.__jsonVal = [cipher.nonce, self.__ciphertext, tag]

        else:  # Crittografia in modalità SENZA AUTENTICAZIONE #
            cipher = AES.new(self.__key, AES.MODE_CBC)
            self.__ciphertext = cipher.encrypt(
                pad(bytes(plaintext, 'utf-8'), AES.block_size))
            self.__jsonKeys = ['iv', 'ciphertext']
            self.__jsonVal = [cipher.iv, self.__ciphertext]

    def decrypt(self, inputObj):
        if self.__auth:
            cipher = AES.new(self.__key, AES.MODE_CCM,
                             nonce=b64decode(inputObj['nonce']))
            self.__plaintext = str(cipher.decrypt_and_verify(
                b64decode(inputObj['ciphertext']), b64decode(inputObj['tag'])), 'utf-8')
        else:
            cipher = AES.new(self.__key, AES.MODE_CBC,
                             b64decode(inputObj['iv']))
            self.__plaintext = str(unpad(cipher.decrypt(
                b64decode(inputObj['ciphertext'])), AES.block_size), 'utf-8')
    # Popolamento oggetto JSON #

    def serialize(self):
        json_values = [b64encode(x).decode('utf-8') for x in self.__jsonVal]
        return json.dumps(dict(zip(self.__jsonKeys, json_values)))

    def deserialize(self, input):
        tmp = json.loads(input)
        if len(tmp) < int(3):
            self.__auth = False
        else:
            self.__auth = True
        return tmp

    # Proprietà classe #

    @property
    def key(self):
        return self.__key

    @key.setter
    def key(self, value):
        self.__key = bytes(value, 'utf-8')

    @property
    def ciphertext(self):
        return self.__ciphertext

    @property
    def auth(self):
        return self.__auth

    @auth.setter
    def auth(self, value):
        self.__auth = value

    @property
    def resJSON(self):
        return self.serialize()

    @property
    def plaintext(self):
        return self.__plaintext


# Messaggi "prompt" per l'utente #
def showPrompt(type):
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

#########################################

# Operazioni su File #


def saveFile(path, content):
    with open(path, "w") as f:
        f.write(content)


def readFile(path):
    with open(path, "r") as f:
        return f.read()

#########################################


def clear(): return os.system('cls')


# MAIN #
while True:
    obj = Crittografia()
    clear()
    tmp = showPrompt("init")
    if tmp == 1:
        clear()
        print("\n\t------------ CHIAVE ------------ ")
        path = showPrompt("path")
        clear()
        try:  # Controllo se file chiave esiste #
            obj.key = b64decode(readFile(path))
            print("File trovato. Importazione chiave...")
        except:  # Genero nuova chiave #
            print("File non trovato --- Genero nuova chiave")
            # Gestione eccezione lunghezza chiave (multiplo di 16) #
            while obj.key == None:
                leng = int(input("Inserisci la lunghezza della chiave: "))
                obj.newKey(leng)
            saveFile(path, b64encode(obj.key).decode('utf-8'))
            input("File generato!\nPremi INVIO per continuare")

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
        print("File criptato generato in: ["+os.getcwd()+"\\"+path+"]")
        input("Premi INVIO per continuare")

    elif tmp == 2:
        clear()
        print("\n\t------------ CHIAVE ------------ ")
        path = showPrompt("path")
        clear()
        try:  # Controllo se file chiave esiste #
            obj.key = readFile(path)
            print("File trovato. Importazione chiave...")
            print("\n\t------------ CIFRATO ------------ ")
            try:
                tmp = obj.deserialize(readFile(showPrompt("path")))
                obj.decrypt(tmp)
                print("\nTesto decriptato: "+obj.plaintext)
                input("\nPremi INVIO per continuare")
            except Exception as e:
                print(str(e))
            #    input("File non trovato. Premi INVIO per continuare")
        except Exception as e:
            print(str(e))
          #  input("Chiave non trovata. Premi INVIO per continuare")
    elif tmp == 3:
        break
    else:
        print("Parametro non valido")
    del obj
