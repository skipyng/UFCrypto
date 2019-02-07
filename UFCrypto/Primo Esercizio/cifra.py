otp = ["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"," "]

key = list(open("chiave.txt").read())

def appendOut(letter,idx):
    tmp = otp.index(letter) + otp.index(key[idx])
    if tmp > len(otp) - 1:
        tmp -= len(otp)
    return otp[tmp]

def cifra(text):
    output = ""
    daCifrare = list(text)
    i = 0
    for x in daCifrare:
        if i < len(key):
           output += appendOut(x,i)
        else:
            i = 0
            output += appendOut(x,i)
        i += 1

    f = open("cifrato.txt","w")
    f.write(output)
    f.close()

cifra(input("Testo da cifrare: ").upper())