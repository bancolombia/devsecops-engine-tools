import os
import platform
from decouple import config

# common_devsecops_lib settings
DEVSECOPS_ENGINE_UTILITIES_PATH = os.path.dirname(os.path.realpath(__file__))
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PLATFORM_SYSTEM = platform.system()
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PLATFORM_RELEASE = platform.release()
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PYTHON_VERSION = platform.python_version()
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PYTHON_COMPILER = platform.python_compiler()
DEVSECOPS_ENGINE_UTILITIES_VERSION = "0.0.3"

# defect-dojo settings
DEBUG = config("DEBUG", default=False, cast=bool)
DISABLE = config("DISABLE", default=False, cast=bool)
SETTING_LOGGER = {"debug": DEBUG, "disable": DISABLE, "log_file": False}
ORGANIZATION_URL = config("ORGANIZATION_URL", default="")
PERSONAL_ACCESS_TOKEN = config("PERSONAL_ACCESS_TOKEN", default="")
REPOSITORY_ID = config("REPOSITORY_ID", default="")
REMOTE_CONFIG_PATH = config("REMOTE_CONFIG_PATH", default="")
PROJECT_REMOTE_CONFIG = config("PROJECT_REMOTE_CONFIG", default="")
TOKEN_CMDB = config("TOKEN_CMDB", default="")
HOST_CMDB = config("HOST_CMDB", default="")
EXPRESSION = config("EXPRESSION", default="")
TOKEN_DEFECT_DOJO = config("TOKEN_DEFECT_DOJO", default="")
HOST_DEFECT_DOJO = config("HOST_DEFECT_DOJO", default="")
SCAN_TYPE = config("SCAN_TYPE", default="")
ENGAGEMENT_NAME = config("ENGAGEMENT_NAME", default="")
FILE = config("FILE", default="")
TAGS = config("TAGS", default="")
