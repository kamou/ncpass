from exceptions import *
import time

import os


class NCObj(object):
    def __init__(self, obj, encrypted=False, keyid=None, keytype=None):
        self.obj = obj
        self.keyid = keyid

        self.keytype = keytype
        self.encrypted = encrypted

    def visit(self, f):
        obj = f(self)
        self.obj = obj.obj
        return self

    def __str__(self):
        return str(self.obj)


class NCList(NCObj):
    def __init__(self, items, **kwargs):
        NCObj.__init__(self, items, **kwargs)
        self.items = items

    def visit(self, f):
        self.items = [item.visit(f) for item in self.items]
        return self

    def __str__(self):
        out = "\n".join([str(item) for item in self.items])
        return out


class PasswordList(NCList):
    def __init__(self, pl, **kwargs):
        NCList.__init__(self, [NCPassObj(p) for p in pl], **kwargs)


class FolderList(NCList):
    def __init__(self, fl, **kwargs):
        NCList.__init__(self, [NCFolderObj(f) for f in fl], **kwargs)


class NCId(NCObj):
    def __init__(self, value, **kwargs):
        if value:
            value = value.strip()
            # TODO: better matching ?
            if len(value) != 36:
                value = None

        NCObj.__init__(self, value)


class NCStr(NCObj):
    def __init__(self, value, **kwargs):
        NCObj.__init__(self, value, **kwargs)


class NCEncStr(NCStr):
    def __init__(self, value, **kwargs):
        NCStr.__init__(self, value, encrypted=True, **kwargs)


class NCEncUrl(NCEncStr):
    def __init__(self, value, **kwargs):
        NCEncStr.__init__(self, value, **kwargs)


class NCCustom(NCObj):
    def __init__(self, value, **kwargs):
        NCObj.__init__(self, value, encrypted=True, **kwargs)


class NCInt(NCObj):
    def __init__(self, value, **kwargs):
        NCObj.__init__(self, value, **kwargs)


class NCStatusCode(NCObj):
    def __init__(self, value, **kwargs):
        NCObj.__init__(self, value, **kwargs)


class NCBool(NCObj):
    def __init__(self, value, **kwargs):
        NCObj.__init__(self, value, **kwargs)


class NCDate(NCObj):
    def __init__(self, value, **kwargs):
        NCObj.__init__(self, value, **kwargs)

    def __str__(self):
        return time.strftime('%d-%m-%y %H:%M:%S', time.localtime(self.obj))


class NCDict(NCObj):
    def __init__(self, obj, props, optprops={}):
        NCObj.__init__(self, obj)

        self.optprops = optprops
        self.props = props | optprops

        keyid = self.obj.get("cseKey", None)
        keyid = None if not keyid else props["cseKey"](keyid)
        self.obj["cseKey"] = keyid

        for prop in self.props:
            if prop == "cseKey":
                continue

            if ((prop not in self.props and prop not in self.optprops)):
                raise NoSuchProperty(prop)

            if (prop not in self.obj):
                continue

            data = self.obj[prop]
            self.obj[prop] = self.props[prop](data, keyid=keyid, keytype=self.obj.get("cseType", None))

    def get(self, prop, default=None):
        if ((prop not in self.props and prop not in self.optprops)):
            raise NoSuchProperty(prop)
        if (prop not in self.obj):
            raise IncompleteObject(prop)

        return self.obj[prop]

    def set(self, prop, value):
        if (prop not in self.props):
            raise NoSuchProperty(prop)
        if (prop not in self.obj):
            raise IncompleteObject(prop)

        self.obj[prop] = value

    def __str__(self):
        out = ""
        for prop in self.props:
            if (prop not in self.obj and prop not in self.optprops):
                raise IncompleteObject(prop)
            if (prop not in self.obj):
                continue
            out += "{}: {}\n".format(prop, str(self.obj[prop]))
        return out

    def visit(self, f):
        for prop in self.props:
            if (prop not in self.obj and prop not in self.optprops):
                raise IncompleteObject(prop)
            if (prop in self.obj and self.obj[prop]):
                self.obj[prop] = self.obj[prop].visit(f)

        return self


class NCPassObj(NCDict):
    __props = {
        "id": NCId,
        "label": NCEncStr,
        "username": NCEncStr,
        "password": NCEncStr,
        "url": NCEncUrl,
        "notes": NCEncStr,
        "customFields": NCCustom,
        "status": NCInt,
        "statusCode": NCStatusCode,
        "hash": NCStr,
        "folder": NCId,
        "revision": NCId,
        "share": NCId,
        "shared": NCBool,
        "cseType":  NCStr,
        "cseKey":  NCId,
        "sseType":  NCId,
        "client":  NCStr,
        "hidden":  NCBool,
        "trashed":  NCBool,
        "favorite":  NCBool,
        "created":  NCDate,
        "updated":  NCDate,
        "edited":  NCDate,
    }

    def __init__(self, password):
        NCDict.__init__(self, password, self.__props)

class NCPassRef(NCDict):
    __props = {
        "id": NCId,
    }
    __optprops = {
        "revision": NCId,
    }

    def __init__(self, ref):
        NCDict.__init__(self, ref, self.__props, self.__optprops)

class NCFolderObj(NCDict):
    __props = {
        "id":  NCId,
        "label": NCEncStr,
        "parent": NCId,
        "revision": NCId,
        "cseType": NCStr,
        "cseKey": NCId,
        "sseType": NCId,
        "client": NCStr,
        "hidden": NCBool,
        "trashed": NCBool,
        "favorite": NCBool,
        "created": NCDate,
        "updated": NCDate,
        "edited": NCDate,
    }
    __optprops = {
        "folders": FolderList,
        "passwords": PasswordList,
    }

    def __init__(self, password):
        NCDict.__init__(self, password, self.__props, self.__optprops)

class NCKeys(NCObj):
    def __init__(self, key):
        NCObj.__init__(self, keychain)
        self.id = id
        self.t = t


class EncryptedKeyChain(NCObj):
    def __init__(self, keychain):
        NCObj.__init__(self, keychain)
        self.csetype, self.data = list(keychain["keys"].items())[0]


class KeyChain(NCObj):
    def __init__(self, keychain):
        NCObj.__init__(self, keychain)
        self.current = self.obj["current"]
        self.keys = self.obj["keys"]


class Challenge(NCObj):
    __props = {
        "challenge:", (False, None)
    }
    def __init__(self, challenge):
        NCObj.__init__(self, challenge)
        challenge = challenge["challenge"]
        self.type = challenge["type"]
        self.salts =  [ bytes.fromhex(salt) for salt in challenge["salts"] ]
        self.password_salt = self.salts[0]
        self.hash_key = self.salts[1]
        self.password_hash_salt = self.salts[2]

    def get(self, n):
        return self.salts[n]

class SettingsObj(NCObj):
    def __init__(self, settings):
        __props = {}
        for key in settings.keys():
            __props[key] = (False, None)
        NCObj.__init__(self, settings)

class ApiObject(object):
    def __init__(self, name, client, actions):
        self.name = name
        self.actions = actions
        self.client = client

    def call(self, command, **kwargs):
        if not (command in self.actions):
            raise InvalidRequest(self.actions[command])

        req = self.actions[command][0]
        __ctr = self.actions[command][1]

        if req == "GET":
            res = self.client.get(os.path.join(self.name, command))
        elif req == "POST":
            res = self.client.post(os.path.join(self.name, command), **kwargs)
        elif req == "DELETE":
            res = self.client.delete(os.path.join(self.name, command), **kwargs)
        else:
            raise NotImplemented(req)

        if __ctr:
            return __ctr(res)

        return res

class PasswordApi(ApiObject):
    actions = {
        "list": ("GET", PasswordList),
        "show": ("POST", NCPassObj),
        "find": ("POST", PasswordList),
        "create": ("POST", NCPassRef),
        "update": ("PATCH", None),
        "delete": ("DELETE", NCPassRef),
        "restore": ("PATCH", None),
    }
    def __init__(self, client):
        ApiObject.__init__(self, "password", client, self.actions)

class FolderApi(ApiObject):
    actions = {
        "list": ("GET", FolderList),
        "show": ("POST", NCFolderObj),
        "find": ("POST", FolderList),
        "create": ("POST", None),
        "update": ("PATCH", None),
        "delete": ("DELETE", None),
        "restore": ("PATCH", None),
    }
    def __init__(self, client):
        ApiObject.__init__(self, "folder", client, self.actions)

class ServiceApi(ApiObject):
    actions = {
        "password": ("POST", None),
    }
    def __init__(self, client):
        ApiObject.__init__(self, "session", client, self.actions)

class SessionApi(ApiObject):
    actions = {
        "request": ("GET", Challenge),
        "open": ("POST", EncryptedKeyChain),
        "close": ("GET", None),
        "keepalive": ("GET", None),
    }
    def __init__(self, client):
        ApiObject.__init__(self, "session", client, self.actions)

class KeyChainApi(ApiObject):
    actions = {
        "get": ("GET", None),
        "set": ("POST", None),
    }
    def __init__(self, client):
        ApiObject.__init__(self, "keychain", client, self.actions)

class SettingsApi(ApiObject):
    actions = {
        "get": ("POST", None),
        "set": ("POST", None),
        "list": ("POST", SettingsObj),
        "reset": ("POST", None),
    }
    def __init__(self, client):
        ApiObject.__init__(self, "settings", client, self.actions)
