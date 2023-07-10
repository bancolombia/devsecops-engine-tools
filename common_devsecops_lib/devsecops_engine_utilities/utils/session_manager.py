import requests

class SessionManager:

    _instance = None

    def __new__(cls):
        if not cls._instance:
            cls._instance = requests.Session()
        return cls._instance
