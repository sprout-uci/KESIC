from cryptography.fernet import Fernet
import hmac
import hashlib
import binascii


def hmac_sha256(key, message):
    byte_key = binascii.unhexlify(key)
    message = binascii.unhexlify(message)
    hmac_val = hmac.new(byte_key, message, hashlib.sha256).hexdigest().upper()
    return hmac_val

def encrypt(key, message):
    fernet = Fernet(key)
    ciphertext_bytes = fernet.encrypt(message.encode())
    ciphertext = ciphertext_bytes.decode('utf-8')
    return ciphertext

def decrypt(key, message):
    fernet = Fernet(key)
    base64_bytes = message.encode('utf-8')
    plaintext_bytes = fernet.decrypt(base64_bytes)
    plaintext = plaintext_bytes.decode('utf-8')
    return plaintext