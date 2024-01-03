import json

with open('C:\\Users\\rnorena\\Documents\\Trabajo talento b\\Sprints\\Sprint 177\\Engine DAST\\NU0429001_devsecops_engine\\result.json', "r") as file:
    json_data = json.load(file)
    print(json_data)