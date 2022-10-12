from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

publicKey = RSA.import_key(open("publicKey.pem").read())
fileName = "LICENSE.txt"


def encryptLicense(fileName, publicKey):
    with open(fileName, "rb") as readLicenseFile:
        licenseFileData = readLicenseFile.read()

    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(publicKey)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(licenseFileData)
    with open("LICENSE", "wb") as writeLicenseFile:
        for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext):
            writeLicenseFile.write(x)
        writeLicenseFile.close()
    print("License File encrypted Successfully !!")


encryptLicense(fileName, publicKey)
