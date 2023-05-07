from tornado.web import authenticated
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .auth import AuthHandler

class UserHandler(AuthHandler):

    # Decrypts the encrypted_data using AES-CTR with the given key and nonce
    def decrypt_data(self, encrypted_data, key, nonce):
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(b64decode(encrypted_data.encode('utf-8'))) + decryptor.finalize()
        return decrypted_data.decode('utf-8')

    # Handles the GET request to retrieve user information
    @authenticated
    def get(self):
        user = self.current_user
        key = user['password']  # The password hash is used as the encryption key
        nonce = b64decode(user['nonce'].encode('utf-8'))

        # Decrypts the user's encrypted information
        decrypted_full_name = self.decrypt_data(user['encrypted_full_name'], key, nonce)
        decrypted_address = self.decrypt_data(user['encrypted_address'], key, nonce)
        decrypted_phone = self.decrypt_data(user['encrypted_phone'], key, nonce)
        decrypted_disabilities = self.decrypt_data(user['encrypted_disabilities'], key, nonce)

        # Sets the response status and builds the response object
        self.set_status(200)
        self.response['email'] = user['email']
        self.response['display_name'] = user['display_name']
        self.response['fullName'] = decrypted_full_name
        self.response['address'] = decrypted_address
        self.response['phone'] = decrypted_phone
        self.response['disabilities'] = decrypted_disabilities

        self.write_json()