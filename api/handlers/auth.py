from datetime import datetime
from time import mktime
from tornado.gen import coroutine

from .base import BaseHandler

class AuthHandler(BaseHandler):

    @coroutine
    def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        try:
            token = self.request.headers.get('X-Token')
            if not token:
              raise Exception()
        except:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return

        # Find the user associated with the provided token in the database
        user = yield self.db.users.find_one({
            'token': token
        }, {
            'email': 1,
            'displayName': 1,
            'expiresIn': 1,
            'password': 1,
            'nonce': 1,
            'encrypted_full_name': 1,
            'encrypted_address': 1,
            'encrypted_phone': 1,
            'encrypted_disabilities': 1
        })

        # If the user is not found, set the current user as None and return an error
        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        # Check if the token has expired
        current_time = mktime(datetime.now().utctimetuple())
        if current_time > user['expiresIn']:
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return

        # Set the current user with the decrypted user information
        self.current_user = {
            'email': user['email'],
            'display_name': user['displayName'],
            'password': user['password'],
            'nonce': user['nonce'],
            'encrypted_full_name': user['encrypted_full_name'],
            'encrypted_address': user['encrypted_address'],
            'encrypted_phone': user['encrypted_phone'],
            'encrypted_disabilities': user['encrypted_disabilities']
        }