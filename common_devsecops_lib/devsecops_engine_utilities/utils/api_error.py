from devsecops_engine_utilities.utils.logger_info import MyLogger
from marshmallow import ValidationError
from requests import Response


class ApiError(ValidationError):
    def __init__(self, message):
        if isinstance(message, dict):
            message = message.get("detail")
        super().__init__({"message": str(message)})
