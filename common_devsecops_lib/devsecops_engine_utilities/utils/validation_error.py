from devsecops_engine_utilities.utils.logger_info import MyLogger
from marshmallow import ValidationError
from requests import Response


class ValidationErrorBase(ValidationError):
    def __init__(self, message):
        super().__init__({"error": message})
