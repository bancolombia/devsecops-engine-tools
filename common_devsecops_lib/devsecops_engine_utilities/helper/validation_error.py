from devsecops_engine_utilities.helper.logger_info import MyLogger
from requests import Response
logger = MyLogger.__call__().get_logger()

class ValidationError(Exception):
    def __init__(self, message):
        if isinstance(message, Response):
            super().__init__(message.json())
        else:
            super().__init__(message)
    