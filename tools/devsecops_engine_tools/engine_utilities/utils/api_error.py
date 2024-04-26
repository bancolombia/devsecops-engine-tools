from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from marshmallow import ValidationError
from requests import Response


class ApiError(ValidationError):
    def __init__(self, message):
        m = ""
        if isinstance(message, dict):
            m = str(message.get("message")) if message.get("message") else ""
            m += str(message.get("detail")) if message.get("detail") else ""
        else:
            m = str(message)
        super().__init__({"message": str(m)})
