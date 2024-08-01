import json

class BearerScanFileMaker:
    def __init__(self):
        self.vulnerabilities = {}

    def add_vulnerabilities(self, scan_result_path):
        with open(scan_result_path, encoding='utf-8') as arc:
            try:
                data = json.load(arc)
                severity = list(data.keys())
                for sev in severity:
                    if sev not in self.vulnerabilities.keys(): 
                        self.vulnerabilities[sev] = []
                    self.vulnerabilities[sev].extend(data[sev])
            except:
                pass
    
    def make_scan_file(self, agent_work_folder):
        with open(
            f"{agent_work_folder}/bearer-scan-vul-man.json", 
            "w"
        ) as file:
            json.dump(self.vulnerabilities, file)
            file.close()
        return f"{agent_work_folder}/bearer-scan-vul-man.json"
        