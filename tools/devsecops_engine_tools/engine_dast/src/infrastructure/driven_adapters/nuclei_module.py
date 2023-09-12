import subprocess
from json import loads

def nuclei(url, templates):
    template = str(templates).replace('[','').replace(']','').replace("'","")

    result = subprocess.run(f'nuclei -u "{url}" -t "{template}" -tags cve -j', stdout=subprocess.PIPE, shell=True, check=True)
    resp = (result.stdout).decode('utf-8')

    resp_json = []
    resp_split = resp.split('}\n{')
    for dc in resp_split:

        if dc.startswith('{') == False:
            dc = '{' + dc
        
        if dc.endswith('}') == False and dc.endswith('}\n') == False:
            dc = dc + '}'

        resp_json.append(loads(dc))

    return resp_json

# print(f"type: {type(resp_json)} \n result: {resp_json}")