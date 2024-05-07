# -*- coding: utf-8 -*-
import logging
import os
import datetime

log_records = []


class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s [%(levelname)s | %(filename)s | %(funcName)s | %(lineno)d] > %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "funcName": record.funcName,
            "lineno": record.lineno
        }
        return log_data


class ListHandler(logging.Handler):
    def emit(self, record):
        log_record = self.format(record)
        log_records.append(log_record)


class SingletonType(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(SingletonType, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class MyLogger(metaclass=SingletonType):
    """resive como parametro bool si es
    True cre un archivo de logs por default is False"""

    _logger = None

    def __init__(self, *args, **kwargs):
        self._logger = logging.getLogger("crumbs")
        if kwargs["debug"]:
            self._logger.setLevel(logging.DEBUG)
        else:
            self._logger.setLevel(logging.WARNING)

        if kwargs["log_file"]:
            now = datetime.datetime.now()
            dirname = "./log"
            if not os.path.isdir(dirname):
                os.mkdir(dirname)
            if kwargs["log_file_format"] == "log":
                # log with file log
                file_handler = logging.FileHandler(
                    dirname + "/log_" + now.strftime("%Y-%m-%d") + ".log"
                )
                formatter = logging.Formatter(
                    "%(asctime)s [%(levelname)s | %(filename)s | %(funcName)s | %(lineno)d] > %(message)s"
                )
                file_handler.setFormatter(formatter)
                self._logger.addHandler(file_handler)
            elif kwargs["log_file_format"] == "json":
                # log with file json
                file_handler = ListHandler()
                file_handler.setFormatter(JsonFormatter())
                self._logger.addHandler(file_handler)
        if kwargs["log_console"]:
            # log whit console
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(CustomFormatter())
            self._logger.addHandler(stream_handler)

    def get_logger(self):
        return self._logger


# forma de llamado
# if __name__ == "__main__":
#     logger = MyLogger.__call__(True)(True).get_logger()
#     logger.info("debug message")
#     logger.info("info message")
#     logger.warning("warning message")
#     logger.error("error message")
#     logger.critical("critical message")
