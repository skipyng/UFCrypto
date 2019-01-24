import json
import os
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class Crittografia:
    def __init__():
        pass
    def __init__(self, auth:bool, keyLen:int):
        self.__auth = auth
        self.__kLen = keyLen

    def newKey(self):
        self.__key = get_random_bytes(self.__kLen)
    

    def crypt(self,plaintext):
        if self.__auth:
            cipher = AES.new(self.__key, AES.MODE_CCM)
            
        else:
            #todo#

        self.__ciphertext, self.__tag = cipher.encrypt_and_digest(bytes(plaintext,'utf-8'))
        self.__nonce = cipher.nonce
     
    def serialize(self):
        json_keys = ['nonce','ciphertext','tag']
        json_values = [ b64encode(x).decode('utf-8') for x in (self.__nonce, self.__ciphertext, self.__tag) ]
        return json.dumps(dict(zip(json_keys,json_values)))
    @property
    def key(self):
        return self.__key
    @property
    def ciphertext(self):
        return self.__ciphertext
    @property
    def auth(self):
        return self.__auth
    @property
    def resJSON(self):
        return self.serialize()


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
def saveFile(path,content):
    with open(path,"w") as f:
        f.write(content)

def readFile(path):
    with open(path,"r") as f:
        return f.read()

#########################################


clear = lambda: os.system('cls')
# MAIN #
while True:
    tmp = showPrompt("init")
    if tmp == 1:
        clear()
        print("\n\t------------ CHIAVE ------------ ")
        path = showPrompt("path")
        len = int(input("Inserisci la lunghezza della chiave: "))
        clear()
        obj = Crittografia(True,len)
        obj.newKey()
        saveFile(path,b64encode(obj.key).decode('utf-8'))
        input("File generato!\nPremi INVIO per continuare")
        
        tmp2 = showPrompt("crypt")
        clear()
        # Scelta modalità (con o senza autenticazione) #
        if tmp2 == 1:
            obj.auth = True
        elif tmp2 == 2:
            obj.auth = False

        obj.crypt(input("Testo da cifrare: "))
        clear()
        print("\n\t------------ CIFRATO ------------ ")
        path = showPrompt("path")
        saveFile(path,obj.resJSON)

    elif tmp == 3:
        break
