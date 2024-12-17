import requests
from requests.adapters import HTTPAdapter

class SessionManager:
    _instance = None
    _token = None
    _host = None

    def __new__(cls, token=None, host=None):
        cls._token = token
        cls._host = host
        if not cls._instance:
            cls._instance = requests.Session()
            adapter = HTTPAdapter(pool_maxsize=40)
            cls._instance.mount('https://', adapter)
            cls._instance.mount('http://', adapter)
        return cls
