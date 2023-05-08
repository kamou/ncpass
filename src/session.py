from nacl.encoding import HexEncoder
from nacl import hash, bindings
from nacl.pwhash import argon2id
from nacl import secret
from api import SessionApi
import pynentry


class Session(SessionApi):
    def __init__(self, client, password_hash=b"", key=b"", password=""):
        SessionApi.__init__(self, client)
        self.password_hash = password_hash
        self.key = key
        

    def request(self):
        return self.call("request")

    def get_master_password(self):
        return pynentry.get_pin(description="description", prompt="password:")

    def hash_password(self, password, challenge):
        args = {
            "digest_size": bindings.crypto_generichash_BYTES_MAX,
            "data": password.encode('utf-8') + challenge.password_salt,
            "key": challenge.hash_key
        }

        password_hash = hash.generichash(**args)
        return HexEncoder.decode(password_hash)
        # return bytes.fromhex(password_hash.decode("utf-8"))

    def init_keys(self):
        pass

    def request_keychain(self, salt):
        challenge = self._kdf(password=self.password_hash, salt=salt)
        return self.call("open", challenge=HexEncoder.encode(challenge).decode("utf-8"))

    def check_dependency(self):
        return (self.password_hash and self.key)

    def authenticate(self, password, challenge):
        self.password_hash = self.hash_password(password, challenge)
        self.keychain = self.request_keychain(challenge.password_hash_salt)

        key = bytes.fromhex(self.keychain.obj["keys"]["CSEv1r1"])
        salt = key[:argon2id.SALTBYTES]
        self.key = self._kdf(password=password.encode("utf-8"), salt=salt)

    def open(self, challenge, password):
        if self.check_dependency():
            self.keychain = self.request_keychain(challenge.password_hash_salt)
        else:
            self.authenticate(password, challenge)
        return self.key, self.keychain


    def close(self):
        return self.call("close")

    def keepalive(self):
        return self.call("keepalive")

    @staticmethod
    def _kdf(password, salt):
        kdf = argon2id.kdf
        ops = argon2id.OPSLIMIT_INTERACTIVE
        mem = argon2id.MEMLIMIT_INTERACTIVE

        key = kdf(size=secret.SecretBox.KEY_SIZE, password=password, salt=salt, opslimit=ops, memlimit=mem)
        return key

