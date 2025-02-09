from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, file_path, encrypted_file_path):
        if not os.path.exists(file_path):
            print("Error: File not found!")
            return
        
        cipher = AES.new(self.key, AES.MODE_CBC)
        iv = cipher.iv  

        with open(file_path, 'rb') as f:
            file_data = f.read()

        padded_data = pad(file_data, AES.block_size)  
        ciphertext = cipher.encrypt(padded_data)

        with open(encrypted_file_path, 'wb') as f:
            f.write(iv + ciphertext)  

        print(f"Encryption complete! Encrypted file saved as: {encrypted_file_path}")

    def decrypt(self, encrypted_file_path, decrypted_file_path):
        """Decrypt the encrypted file and restore the original"""
        if not os.path.exists(encrypted_file_path):
            print("Error: Encrypted file not found!")
            return

        with open(encrypted_file_path, 'rb') as f:
            iv = f.read(16)
            ciphertext = f.read()

        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(ciphertext)
        original_data = unpad(decrypted_padded_data, AES.block_size)

        with open(decrypted_file_path, 'wb') as f:
            f.write(original_data)

        print(f"Decryption complete! Decrypted file saved as: {decrypted_file_path}")
key = os.urandom(16)

file_path = input("Enter the full path of the file to encrypt: ").strip()

encrypted_file_path = file_path + ".enc"  
decrypted_file_path = file_path.replace(".", "_decrypted.")  

aes_cipher = AESCipher(key)
aes_cipher.encrypt(file_path, encrypted_file_path)
aes_cipher.decrypt(encrypted_file_path, decrypted_file_path)
