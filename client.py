import requests
import logging
import binascii
import json
import os
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
import cryptography.hazmat.backends as backends
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger('root')
FORMAT = "[%(asctime)s %(filename)s:%(lineno)s] %(message)s"
logging.basicConfig(format=FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

def register(username, master_password):
    logger.info("Registering account...")
    
    # derive 100100 times to get encryption key
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=username.encode('latin'), iterations=100100, backend=backends.default_backend())
    encryption_key = kdf.derive(master_password.encode('latin'))
    logger.info("encryption_key: " + str(encryption_key))

    # derive 1 more time to get authentication hash
    kdf_once = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=username.encode('latin'), iterations=1, backend=backends.default_backend())
    authentication_hash = kdf_once.derive(encryption_key)
    logger.info("authentication_hash: " + str(authentication_hash))

    # encrypt an empty dictionary which will be our vault
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(encryption_key), mode=modes.CBC(iv), backend=backends.default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    data = iv + encryptor.update(padder.update(json.dumps(dict()).encode('latin')) + padder.finalize()) + encryptor.finalize()
    logger.info("encrypted_vault: " + str(data))

    # transform to base64 to send in json
    data = binascii.b2a_base64(data).decode('latin').strip()
    authentication_hash = binascii.b2a_base64(authentication_hash).decode('latin').strip()

    logger.info("Sending to server...")
    req = requests.post(f'{SERVER_URL}/api/register', data=json.dumps({'username': username, 'auth': authentication_hash, 'vault': data}))
    if req.status_code == 200:
        logger.info("Account Registered Successfully!")
    else:
        logger.info("There was an error...")

def getVault(username, master_password):
    # derive 100100 times to get encryption key
    logger.info("deriving encryption key...")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=username.encode('latin'),
        iterations=100100, backend=backends.default_backend())
    encryption_key = kdf.derive(master_password.encode('latin'))
    logger.info("encryption_key: " + str(encryption_key))

    # derive 1 more time to get authentication hash
    logger.info("deriving authentication hash...")
    kdf_once = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=username.encode('latin'),
        iterations=1, backend=backends.default_backend())
    authentication_hash = kdf_once.derive(encryption_key)
    logger.info("authentication_hash: " + str(authentication_hash))

    # transform to base64 to send in json
    authentication_hash = binascii.b2a_base64(authentication_hash).decode('latin').strip()

    logger.info("requesting vault to the server...")
    req = requests.get(f'{SERVER_URL}/api/vault', data=json.dumps({'username': username, 'auth': authentication_hash}))
    if req.status_code == 200:
        vault = req.content
        logger.info("Vault received!")
        logger.info("encrypted_vault: " + str(vault))
    else:
        logger.info("There was an error...")
        return
    
    # decrypt the vault
    logger.info("decrypting vault...")
    iv = vault[0:16]
    cipher = Cipher(algorithms.AES(encryption_key), mode=modes.CBC(iv), backend=backends.default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()

    vault = unpadder.update(decryptor.update(vault[16:]) + decryptor.finalize()) + unpadder.finalize()
    vault = json.loads(vault.decode('latin'))
    logger.info("vault: " + str(vault))
    return vault

def appendVault(username, master_password, vault, website, password):
    print("Appending to vault...")
    vault[website] = password

    # derive 100100 times to get encryption key
    logger.info("deriving encryption key...")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=username.encode('latin'), iterations=100100, backend=backends.default_backend())
    encryption_key = kdf.derive(master_password.encode('latin'))
    logger.info("encryption_key: " + str(encryption_key))

    # derive 1 more time to get authentication hash
    logger.info("deriving authentication hash...")
    kdf_once = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=username.encode('latin'), iterations=1, backend=backends.default_backend())
    authentication_hash = kdf_once.derive(encryption_key)
    logger.info("authentication_hash: " + str(authentication_hash))

    # encrypt the vault
    logger.info("encrypting the new vault...")
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(encryption_key), mode=modes.CBC(iv), backend=backends.default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    data = iv + encryptor.update(padder.update(json.dumps(vault).encode('latin')) + padder.finalize()) + encryptor.finalize()
    logger.info("encrypted_vault: " + str(data))

    # transform to base64 to send in json
    logger.info("requesting vault to the server...")
    data = binascii.b2a_base64(data).decode('latin').strip()
    authentication_hash = binascii.b2a_base64(authentication_hash).decode('latin').strip()

    req = requests.post(f'{SERVER_URL}/api/vault', data=json.dumps({'username': username, 'auth': authentication_hash, 'vault': data}))
    if req.status_code == 200:
        logger.info("Vault Updated Successfully!")
        logger.info("new vault: " + str(vault))
        return vault
    else:
        logger.info("There was an error...")

print("Password Manager Client")
username = input("username?")
master_password = input("password?")
register(username, master_password)
vault = {}
while True:
    print("\n0-Exit")
    print("1-Get Vault")
    print("2-Add Password")
    option = int(input("Option?"))

    if option==0:
        break

    elif option==1:
        vault = getVault(username, master_password)
        if vault == None:
            break

    elif option==2:
        website = input("website?")
        password = input("password?")
        vault = appendVault(username, master_password, vault, website, password)
        if vault == None:
            break