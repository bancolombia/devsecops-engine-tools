import os
import platform

# common_defect_dojo.settings
DEVSECOPS_ENGINE_UTILITIES_PATH = os.path.dirname(os.path.realpath(__file__))
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PLATFORM_SYSTEM = platform.system()
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PLATFORM_RELEASE = platform.release()
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PYTHON_VERSION = platform.python_version()
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PYTHON_COMPILER = platform.python_compiler()
DEVSECOPS_ENGINE_UTILITIES_VERSION = "0.0.1"
