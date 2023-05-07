from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode
from tornado.gen import coroutine
from uuid import uuid4
from base64 import b64decode
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .base import BaseHandler

class LoginHandler(BaseHandler):

    # Hashes the password using the Scrypt key derivation function with the given salt
    def hash_password(self, password, salt):
        kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
        return kdf.derive(password.encode('utf-8'))

    # Generates an authentication token for the user with a 2-hour expiration time
    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        # Updates the user's token and expiration time in the database
        yield self.db.users.update_one({
            'email': email
        }, {
            '$set': token
        })

        return token

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
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        # Validates the email and password
        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        # Fetches the user's password and salt from the database
        user = yield self.db.users.find_one({
            'email': email
        }, {
            'password': 1,
            'salt': 1
        })

        # Checks if the user exists and the password is correct
        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return

        salt = b64decode(user['salt'].encode('utf-8'))
        hashed_password = self.hash_password(password, salt)

        if user['password'] != hashed_password:
            self.send_error(403, message='The email address and password are invalid!')
            return

        # Generates a new token for the user and sends it in the response
        token = yield self.generate_token(email)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()