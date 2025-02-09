from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, file_path, output_path):
        cipher = AES.new(self.key, AES.MODE_CBC)
        iv = cipher.iv  #initialization Vector

        with open(file_path, 'rb') as f:
            plaintext = f.read()

        padded_text = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        with open(output_path, 'wb') as f:
            f.write(iv + ciphertext)  

    def decrypt(self, file_path, output_path):
        with open(file_path, 'rb') as f:  
            iv = f.read(16) 
            ciphertext = f.read()

        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_padded_text = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_padded_text, AES.block_size)

        with open(output_path, 'wb') as f:  
            f.write(plaintext)

key = os.urandom(16)

input_file = "report.txt"
encrypted_file = "encrypted.bin"
decrypted_file = "decrypted.txt"

aes_cipher = AESCipher(key)

aes_cipher.encrypt(input_file, encrypted_file)
print("Encryption Complete. Encrypted file saved as", encrypted_file)

aes_cipher.decrypt(encrypted_file, decrypted_file)
print("Decryption Complete. Decrypted file saved as", decrypted_file)

