import sys
import ncp

class NCPApp(object):
    def __init__(self, url="https://try.nextcloud.com"):
        self.commands = {"raw": self.raw, "list": self.list, "get": self.get}
        self.ncp = ncp.NCP(url)

    def command(self, service, command):
        return self.ncp.handle(service, command)

    def get_folders(self):
        return self.command("folder", "list")

    def get_passwords(self):
        return self.command("password", "list")

    def list(self, service, by="label"):
        objlist = self.command(service, "list")
        for item in objlist.items:
            obj = self.ncp.decrypt_object(item)
            print("{} [{}]".format(obj.get(by), obj.get("id")))

    def get(self, service, id=None, by=None):
        if id:
            obj = self.ncp.handle(service, "show", id=id)
            obj = self.ncp.decrypt_object(obj)
            if by:
                obj = obj.get(by)
        else:
            obj = self.ncp.handle(service, "list")
        print(obj)

    def raw(self, service, cmd, **kwargs):
        obj = self.ncp.handle(service, cmd, **kwargs)
        if obj:
            obj = self.ncp.decrypt_object(obj)
        print(obj)

    @staticmethod
    def handle():
        app = NCPApp()
        cmd = sys.argv[1]
        if cmd not in app.commands:
            raise ncp.UnknownCommand(cmd)

        f = app.commands[cmd]
        if cmd == "raw":
            service = sys.argv[2]
            cmd = sys.argv[3]
            args = sys.argv[4:]
            opts = {}
            for arg in args:
                if not (("=" in arg) and arg.startswith("--")):
                    raise ncp.InvalidArgument(f"Invalid argument {arg}")
                if arg.endswith("="):
                    raise ncp.InvalidArgument("Usage is: --key=value, no space allowed")
                name, value = arg[2::].split("=", 1)
                if "," in value:
                    value = value.split(",")
                opts[name] = value
            f(service=service, cmd=cmd, **opts)
        else:
            f(*sys.argv[2:])
