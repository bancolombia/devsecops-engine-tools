from devsecops_engine_utilities.utils.logger_info import MyLogger
from requests import Response


class ValidationError(Exception):
    def __init__(self, message):
        if isinstance(message, Response):
            super().__init__(message.json())
        else:
            super().__init__(message)
