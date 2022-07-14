from Crypto.PublicKey import RSA

def generateKey():
    key = RSA.generate(2048)
    publicKey = key.publickey().export_key()
    with open("publicKey.pem", "wb") as writePublicKey:
        writePublicKey.write(publicKey)
        writePublicKey.close()
    print("Public Key Created Successfully !!")

    privateKey = key.export_key()
    with open("privateKey.pem", "wb") as writePrivateKey:
        writePrivateKey.write(privateKey)
        writePrivateKey.close()
    print("Private Key Created Successfully !!")
generateKey()