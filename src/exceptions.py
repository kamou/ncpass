class NotImplemented(Exception):
    def __init__(self, name):
        self.res = name
        self.message = f"{name} requests are not yet implemented"
        super().__init__(self.message)

class DecryptionError(Exception):
    pass

class ResponseError(Exception):
    def __init__(self, res):
        self.res = res

class RequestError(Exception):
    def __init__(self, res):
        self.res = res

class LoginError(Exception):
    def __init__(self, res):
        self.res = res

class UnknownService(Exception):
    def __init__(self, svc):
        self.svc = svc

class UnknownCommand(Exception):
    def __init__(self, cmd):
        self.cmd = cmd

class NoSuchProperty(Exception):
    def __init__(self, prop):
        self.prop = prop

class IncompleteObject(Exception):
    def __init__(self, prop):
        self.prop = prop

class InvalidRequest(Exception):
    def __init__(self, req):
        self.prop = req

class InvalidArgument(Exception):
    def __init__(self, args):
        self.prop = args
