import subprocess
from json import loads
import re


def nuclei(url, templates=None, tags=None, token=None, flags=None):
    file_name = "results.json"
    if (templates is not None) and (tags is None):
        template = str(templates).replace("[", "").replace("]", "").replace("'", "")
        result = subprocess.run(
            f'nuclei -u {url} -t {template} -j -nc -H "Authorization: Bearer {token}" {flags}',
            shell=True,
            capture_output=True,
        )
        resp = (result.stdout).decode("utf-8")
    elif (templates is None) and (tags is not None):
        template = str(templates).replace("[", "").replace("]", "").replace("'", "")
        result = subprocess.run(
            f'nuclei -u {url} -tags {tags} -j -nc -H "Authorization: Bearer {token}" {flags}',
            shell=True,
            capture_output=True,
        )
        resp = (result.stdout).decode("utf-8")
    elif (templates is not None) and (tags is not None):
        template = str(templates).replace("[", "").replace("]", "").replace("'", "")
        result = subprocess.run(
            f"nuclei -u {url} -tags {tags} -t {template} -j -nc -H Authorization: Bearer {token} {flags}",
            shell=True,
            capture_output=True,
        )
        resp = (result.stdout).decode("utf-8")
    resp_json = []

    resp_split = resp.split("}\n{")

    for dc in resp_split:
        if dc.startswith("{") == False:
            dc = "{" + dc

        if dc.endswith("}") == False and dc.endswith("}\n") == False:
            dc = dc + "}"
        match = re.search(
            r'\{"template":.*\}', dc
        )  # Busca el patrón '{"template":' seguido de cualquier cosa
        result = ""
        if match:
            result = (
                match.group()
            )  # Obtiene la parte de la cadena que coincide con el patrón
        if result != "":
            resp_json.append(loads(result))
        else:
            resp_json.append(loads("{}"))

    return resp_json


# print(f"type: {type(resp_json)} \n result: {resp_json}")
