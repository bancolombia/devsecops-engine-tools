import os
import platform

# common_devsecops_lib settings
DEVSECOPS_ENGINE_UTILITIES_PATH = os.path.dirname(os.path.realpath(__file__))
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PLATFORM_SYSTEM = platform.system()
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PLATFORM_RELEASE = platform.release()
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PYTHON_VERSION = platform.python_version()
DEVSECOPS_ENGINE_UTILITIES_RUNNER_PYTHON_COMPILER = platform.python_compiler()
DEVSECOPS_ENGINE_UTILITIES_VERSION = "0.0.1"

# remote
PERSONAL_ACCESS_TOKEN = "wq2rs7faqtp6xn64m5gezgoxw3ifs5ypomvugrt2v4xglveq3shq"
REMOTE_CONFIG_REPO = "https://grupobancolombia.visualstudio.com/Vicepresidencia%20Servicios%20de%20Tecnolog%C3%ADa/_git/NU0429001_DevSecOps_Remote_Config"
REMOTE_CONFIG_PATH = "https://grupobancolombia.visualstudio.com/Vicepresidencia%20Servicios%20de%20Tecnolog%C3%ADa/_git/NU0429001_DevSecOps_Remote_Config"
print(REMOTE_CONFIG_PATH)
SYSTEM_TEAM_PROJECT_ID = ""
# ORGANIZATION_URL = "https://dev.azure.com/PNFEngineTest/"
ORGANIZATION_URL = "https://grupobancolombia.visualstudio.com/Vicepresidencia%20Servicios%20de%20Tecnolog%C3%ADa"
        
print(ORGANIZATION_URL)