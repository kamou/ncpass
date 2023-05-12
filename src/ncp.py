import json
import pynentry
import os
from exceptions import *
from client import Client
from api import PasswordApi, FolderApi, SessionApi, KeyChainApi, ServiceApi, SettingsApi, KeyChain
from session import Session
from nacl import secret
import gnupg
from nacl.pwhash import argon2id
import configparser

class NCP(object):
    __services = {
        "password": PasswordApi,
        "folder": FolderApi,
        "session": SessionApi,
        "keychain": KeyChainApi,
        "service": ServiceApi,
        "settings": SettingsApi,
    }

    def __init__(self):
        home = os.environ["HOME"]
        gpg_path = os.path.join(home, ".passwords")
        if (os.path.exists(os.path.join(gpg_path, "server"))):
            self.url = open(os.path.join(gpg_path, "server"), "r").read()
        else:
            self.url = input("server url: ")
            print(self.url)

        self.client = Client(self.url)
        self.ap = None
        self.key = b""
        self.password_hash = b""
        self.password = ""
        self.gpg_keyid = None
        self.config = configparser.ConfigParser()
        self.config.add_section("general")

        self.login(self.url)

    def login(self, url):
        home = os.environ["HOME"]
        gpg_path = os.path.join(home, ".passwords")
        os.makedirs(gpg_path, exist_ok = True, mode=0o700)
        open(os.path.join(gpg_path, "server"), "w").write(url)
        # prepare the keystore (will be created if not exist)
        os.makedirs(gpg_path, exist_ok = True, mode=0o700)

        self.gpg = gnupg.GPG(gnupghome=gpg_path, use_agent=True)
        self.load_config()

        self.session = Session(self.client, self.password_hash, self.key)

        try:
            challenge = self.session.request()
        except ResponseError as e:
            if (e.res.status_code != 401):
                raise e
            self.ap = self.client.request_ap()
            self.client.set_ap(self.ap["loginName"], self.ap["appPassword"])
            challenge = self.session.request()

        keys = [ key["fingerprint"] for key in self.gpg.list_keys() ]
        if self.config["general"].get("id", "INVALID") not in keys:
            self.password = self.get_master_password()
            self.create_local_storage_key(self.password)

        self.key, keychain = self.session.open(challenge, self.password)
        payload = bytes.fromhex(keychain.data)[argon2id.SALTBYTES:]

        self.keychain = KeyChain(json.loads(self._decrypt(payload, self.key)))
        self.save_config()

    def request_challenge(self):
        try:
            challenge = self.session.request()
            return challenge
        except: # TODO add correct exception handling + status code
            return None

    def get_master_password(self):
        password =  pynentry.get_pin(description="Master Password", prompt="Password:")
        confirmation =  pynentry.get_pin(description="Confirm Master Password", prompt="Password:")
        if password == confirmation:
            return password
        return None

    def save_config(self):
        data = dict()
        data["password_hash"] = self.session.password_hash.hex()
        data["key"] = self.session.key.hex()
        data["apppassword"] = self.ap
        data["keychain"] = self.keychain.obj

        data = json.dumps(data)
        data = str(self.gpg.encrypt(data, self.config["general"]["id"]))

        home = os.environ["HOME"]
        path = os.path.join(home, ".passwords/.pwcache")

        fd = os.open(
            path=path,
            flags=(
                os.O_WRONLY
                | os.O_CREAT
                | os.O_TRUNC
            ),
            # don't touch my tralala
            mode=0o600
        )

        with open(fd, "w") as of:
            of.write(data)

        home = os.environ["HOME"]
        path = os.path.join(home, ".passwords/rc")

        with open(path, 'w') as configfile:
            self.config.write(configfile)

    def create_local_storage_key(self, password):
        input_data = self.gpg.gen_key_input(passphrase=password)
        key = self.gpg.gen_key(input_data)
        assert key
        self.config["general"]["id"] = str(key)

    def load_config(self):
        home = os.environ["HOME"]
        path = os.path.join(home, ".passwords/rc")
        self.config.read(path)

        home = os.environ["HOME"]
        path = os.path.join(home, ".passwords/.pwcache")
        if os.path.exists(path):
            with open(path, "rb") as f:
                data = f.read()

                # empy, just return
                if not data: return

                data = str(self.gpg.decrypt(data)).strip()

                # decryption failed, notify
                if not data: raise DecryptionError()

                # deserialize
                creds = json.loads(data)
                self.key = bytes.fromhex(creds.get("key", ""))

                self.password_hash = bytes.fromhex(creds.get("password_hash", ""))

                self.ap = creds.get("apppassword", None)
                self.client.set_ap(self.ap["loginName"], self.ap["appPassword"])

                self.keychain = KeyChain(creds.get("keychain"))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.client.close()

    def get(self, service, path):
        return self.client.get(os.path.join(service, path))

    def decrypt(self, cipherset, keyid):
        key = bytes.fromhex(self.keychain.obj.get("keys")[keyid.obj])
        return self._decrypt(cipherset, key)

    def _decrypt(self, cipherset, key):
        nonce = cipherset[:secret.SecretBox.NONCE_SIZE]
        ciphertext = cipherset[secret.SecretBox.NONCE_SIZE:]
        sb = secret.SecretBox(key)
        return sb.decrypt(ciphertext, nonce=nonce).decode("utf-8")

    def hex2bytes(self, hexstr):
            try: return bytes.fromhex(hexstr)
            except ValueError: return b""

    def decrypt_object(self, obj):
        def decrypt(obj):
            if obj and obj.keyid and obj.encrypted:
                if rawdata := self.hex2bytes(obj.obj):
                    obj.obj = self.decrypt(rawdata, obj.keyid)
                    obj.encrypted = False
            return obj

        return obj.visit(decrypt)

    def decrypt_list(self, l):
        for item in l.items:
            self.decrypt_object(item)
        return l

    def handle(self, service, command, **kwargs):
        if not (svc := self.__services.get(service, None)):
            raise UnknownService(service)
        svc = svc(self.client)
        return svc.call(command, **kwargs)
