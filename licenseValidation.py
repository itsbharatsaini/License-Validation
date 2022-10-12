from ast import Global
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import datetime
import os.path
import requests

if  os.path.exists("privateKey.pem") :
    if  os.path.exists('LICENSE') :
        pass
    else:
        print("Error : Please provide LICENSE file.")
        exit()
else:
    print("Error : Please provide privateKey.pem file.")
    exit()

privateKey = RSA.import_key(open("privateKey.pem").read())
fileName = 'LICENSE'

def decryptLicense(fileName,privateKey):
    try:
        readLicenseFile = open(fileName, "rb")
        enc_session_key, nonce, tag, ciphertext = [ readLicenseFile.read(x) for x in (privateKey.size_in_bytes(), 16, 16, -1) ]

        cipher_rsa = PKCS1_OAEP.new(privateKey)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        licenseData = cipher_aes.decrypt_and_verify(ciphertext, tag)
        licenseData = licenseData.decode("utf-8").split('\n')
        # print(licenseData)
        licenseExpiration = ''.join(filter(str.isdigit, licenseData[-1]))
        return licenseExpiration
    except:
        print("Error : Invalid Private Key.")
        exit()

def licenseValidation(licenseExpiration):
    apiURL = "https://worldtimeapi.org/api/timezone/Asia/Kolkata"
    result = requests.get(url = apiURL)
    timeZoneData = result.json()
    todayDate = timeZoneData['datetime'][:10]
    todayDate = int(todayDate[:4] + todayDate[5:7] + todayDate[8:10])

    if int(licenseExpiration) >= todayDate:
        return True
    else:
        licenseExpiredDate = datetime.datetime.strptime(licenseExpiration, '%Y%m%d')
        print("License Expired : ",licenseExpiredDate)
        return False

Result = licenseValidation(decryptLicense(fileName,privateKey))
print("License Validation : ", Result)
