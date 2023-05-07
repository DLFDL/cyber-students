import os
from tornado.escape import json_decode
from tornado.gen import coroutine
from base64 import b64encode
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .base import BaseHandler

class RegistrationHandler(BaseHandler):

    # Define a method to hash the password using the Scrypt key derivation function
    def hash_password(self, password, salt):
        kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
        return kdf.derive(password.encode('utf-8'))

    # Define a method to encrypt sensitive user data using AES-CTR encryption
    def encrypt_data(self, data, key, nonce):
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
        return b64encode(ct).decode('utf-8')

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            full_name = body.get('fullName')
            if not isinstance(full_name, str):
                raise Exception()
            address = body.get('address')
            if not isinstance(address, str):
                raise Exception()
            phone = body.get('phone')
            if not isinstance(phone, str):
                raise Exception()
            disabilities = body.get('disabilities')
            if not isinstance(disabilities, str):
                raise Exception()
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password, display name, '
                                         'full name, address, phone, and disabilities')
            return

        # Check if input fields are not empty
        # If empty, send an error message
        if not full_name:
            self.send_error(400, message='Please enter a full name')
            return
        if not address:
            self.send_error(400, message='Please enter an address')
            return
        if not phone:
            self.send_error(400, message='Please enter a phone number')
            return
        if not disabilities:
            self.send_error(400, message='If this field does not apply please enter N/A')
            return

        # Check if a user with the given email already exists
        user = yield self.db.users.find_one({
            'email': email
        }, {})
        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        # If not, create a new user with the provided information
        # Encrypt information
        salt = os.urandom(16)
        hashed_password = self.hash_password(password, salt)
        encryption_key = hashed_password
        nonce = os.urandom(16)

        encrypted_full_name = self.encrypt_data(full_name, encryption_key, nonce)
        encrypted_address = self.encrypt_data(address, encryption_key, nonce)
        encrypted_phone = self.encrypt_data(phone, encryption_key, nonce)
        encrypted_disabilities = self.encrypt_data(disabilities, encryption_key, nonce)

        # Insert the new user into the database with the encrypted data
        yield self.db.users.insert_one({
            'email': email,
            'password': hashed_password,'salt': b64encode(salt).decode('utf-8'),
            'displayName': display_name,
            'encrypted_full_name': encrypted_full_name,
            'encrypted_address': encrypted_address,
            'encrypted_phone': encrypted_phone,
            'encrypted_disabilities': encrypted_disabilities,
            'nonce': b64encode(nonce).decode('utf-8')
        })

        self.set_status(200)
        self.response['email'] = email  # Return original email in response
        self.response['displayName'] = display_name  # Return original display name in response

        self.write_json()