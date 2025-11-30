from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64

class AESCipher:
    def __init__(self, key: str):

        if len(key) != 13:
            raise ValueError("Key must be exactly 13 characters long.")
        

        key_bytes = key.encode('utf-8')
        

        salt = b'static_salt_123'  
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16, 
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        self.key = kdf.derive(key_bytes)

    def encrypt(self, plaintext: str) -> str:

        iv = os.urandom(16)
        

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        

        encrypted = base64.b64encode(iv + ciphertext).decode('utf-8')
        return encrypted

    def decrypt(self, encrypted: str) -> str:

        data = base64.b64decode(encrypted)
        iv = data[:16]
        ciphertext = data[16:]
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode('utf-8')
    

if __name__ == "__main__":
    flag = dec