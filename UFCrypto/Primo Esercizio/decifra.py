otp = ["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"," "]

key = list(open("chiave.txt").read())
cifrato = open("cifrato.txt").read()

def appendOut(letter,idx):
    tmp = otp.index(letter) - otp.index(key[idx])
    if tmp < 0:
        tmp += len(otp)
    return otp[tmp]

def decifra(text):
    output = ""
    daDecifrare = list(text)
    i = 0
    for x in daDecifrare:
        if i < len(key):
           output += appendOut(x,i)
        else:
            i = 0
            output += appendOut(x,i)
        i += 1

    print("Testo decifrato\n")
    print(output,"\n")

decifra(cifrato)