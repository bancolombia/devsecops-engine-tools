import json
from devsecops_engine_utilities.settings import DEVSECOPS_ENGINE_UTILITIES_PATH


def get_response(name_file: str):
    with open(f"{DEVSECOPS_ENGINE_UTILITIES_PATH}/defect_dojo/test/files/{name_file}", "r") as fp:
        data = json.load(fp)
        return data
