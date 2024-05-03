import os
import json
import platform
from decouple import config

# common_devsecops_lib settings
DEVSECOPS_ENGINE_UTILITIES_PATH = os.path.dirname(os.path.realpath(__file__))
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PLATFORM_SYSTEM = platform.system()
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PLATFORM_RELEASE = platform.release()
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PYTHON_VERSION = platform.python_version()
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PYTHON_COMPILER = platform.python_compiler()

# logging settings
DEBUG_DEVSECOPS = config("DEBUG_DEVSECOPS", default=False, cast=bool)
LOG_CONSOLE_DEVSECOPS = config("LOG_CONSOLE_DEVSECOPS", default=False, cast=bool)
FILE_DEBUG_DEVSECOPS = config("FILE_DEBUG_DEVSECOPS", default=False, cast=bool)
FILE_FORMAT_DEBUG_DEVSECOPS = config("FILE_FORMAT_DEBUG_DEVSECOPS", default="log", cast=str)
SETTING_LOGGER = {"debug": DEBUG_DEVSECOPS, "log_console": LOG_CONSOLE_DEVSECOPS, "log_file": FILE_DEBUG_DEVSECOPS, "log_file_format": FILE_FORMAT_DEBUG_DEVSECOPS}

# defect-dojo settings
INTEGRATION_TEST = config("INTEGRATION_TEST", default=False, cast=bool)
ORGANIZATION_URL = config("ORGANIZATION_URL", default="")
PERSONAL_ACCESS_TOKEN = config("PERSONAL_ACCESS_TOKEN", default="", cast=str)
REPOSITORY_ID = config("REPOSITORY_ID", default="", cast=str)
REMOTE_CONFIG_PATH = config("REMOTE_CONFIG_PATH", default="")
PROJECT_REMOTE_CONFIG = config("PROJECT_REMOTE_CONFIG", default="", cast=str)
TOKEN_CMDB = config("TOKEN_CMDB", default="", cast=str)
HOST_CMDB = config("HOST_CMDB", default="", cast=str)
EXPRESSION = config("EXPRESSION", default="", cast=str)
TOKEN_DEFECT_DOJO = config("TOKEN_DEFECT_DOJO", default="", cast=str)
HOST_DEFECT_DOJO = config("HOST_DEFECT_DOJO", default="", cast=str)
SCAN_TYPE = config("SCAN_TYPE", default="", cast=str)
CMDB_MAPPING = json.loads(config("CMDB_MAPPING", default={}, cast=str))
ENGAGEMENT_NAME = config("ENGAGEMENT_NAME", default="", cast=str)
FILE = config("FILE", default="", cast=str)
TAGS = config("TAGS", default="", cast=str)
COMPACT_REMOTE_CONFIG_URL = config("COMPACT_REMOTE_CONFIG_URL", default="", cast=str)
BRANCH_TAG = config("BRANCH_TAG", default="", cast=str)
