from telnetlib import STATUS
from time import process_time_ns
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from datetime import date

from rsa import decrypt

privateKey = RSA.import_key(open("privateKey.pem").read())
fileName = 'LICENSE'

def decryptLicense(fileName,privateKey):
    readLicenseFile = open(fileName, "rb")
    enc_session_key, nonce, tag, ciphertext = [ readLicenseFile.read(x) for x in (privateKey.size_in_bytes(), 16, 16, -1) ]

    cipher_rsa = PKCS1_OAEP.new(privateKey)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    licenseData = cipher_aes.decrypt_and_verify(ciphertext, tag)
    licenseData = licenseData.decode("utf-8").split('\n')
    # print(licenseData)
    licenseExpiration = int(''.join(filter(str.isdigit, licenseData[-1])))
    return licenseExpiration

def licenseValidation(licenseExpiration):
    today = date.today()
    today = int(today.strftime("%Y%m%d"))
    if licenseExpiration >= today:
        return True
    else:
        return False

# Result = licenseValidation(decryptLicense(fileName,privateKey))
print("License Validation : ", licenseValidation(decryptLicense(fileName,privateKey)))
