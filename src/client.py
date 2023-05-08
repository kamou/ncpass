from exceptions import *
import webbrowser
import requests
import json
import os


class Client(object):
    APP_PATH = "index.php/apps/passwords/api/1.0/"
    LOGIN_PATH = "index.php/login/v2"

    def __init__(self, url):
        self.url = url

        self._session = requests.session()
        self._session.verify = True
        self.headers = {}

    def set_ap(self, username, password):
        """ Sets the application password

        :param username: application user name
        :param password: application password
        """
        self._session.auth = (username, password)

    def request_ap(self):
        """ Requests a new application password

        :returns: The application password
        :raises: ResponseError in case of failed app authentication
        """
        path = os.path.join(self.url, Client.LOGIN_PATH)
        res = self._session.post(path, verify=True, headers=self.headers)
        if res.status_code != 200:
            raise LoginError(res)
        request = json.loads(res.content)

        print("Please go to your browser to grant access to the app")
        webbrowser.open(request["login"])
        token = request["poll"]["token"]
        endpoint = request["poll"]["endpoint"]

        while True:
            res = self._session.post(endpoint, json={"token": token}, verify=True, headers=self.headers)
            if res.status_code == 200: break
            else: raise ResponseError(res)

        return json.loads(res.content)

    def post(self, path, **kwargs):
        """ Performs a POST request to the http saerver

        :param path: path to the api endpoint
        :param args: POST data
        :raises: ResponseError if the request failed
        :returns: The
        """
        path = os.path.join(Client.APP_PATH, path)
        res = self._session.post(os.path.join(self.url, path), json=kwargs, verify=True, headers=self.headers)
        self.headers["X-API-SESSION"] = res.headers["X-API-SESSION"]

        if res.status_code in  [200, 201]:
            return json.loads(res.content)
        raise ResponseError(res)

    def get(self, path):
        """ Performs a GET request to the http saerver

        :param path: path to the api endpoint
        """
        path = os.path.join(Client.APP_PATH, path)
        res = self._session.get(os.path.join(self.url, path), stream=True, verify=True, headers=self.headers)
        self.headers["X-API-SESSION"] = res.headers["X-API-SESSION"]

        if res.status_code == 200:
            return json.loads(res.content)
        raise ResponseError(res)

    def close(self):
        if self._session:
            self._session.close()
