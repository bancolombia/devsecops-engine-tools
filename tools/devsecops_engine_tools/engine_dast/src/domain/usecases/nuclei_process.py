from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei_module import nuclei
from devsecops_engine_tools.engine_dast.src.domain.model.Scan import Scan
from devsecops_engine_tools.engine_dast.src.domain.model.ResultScan import ResultScan
from devsecops_engine_tools.engine_dast.src.domain.model.Template import Template
from devsecops_engine_tools.engine_dast.src.domain.model.Vulnerability import Vulnerability
from prettytable import PrettyTable, DOUBLE_BORDER

class NucleiProcess:
    def __init__(self, scan: Scan):
        self.data = scan.data
        self.resultScans: list[ResultScan] = []
        self.vulnerablities_list: list[Vulnerability] = []

    def get_result_scans(self):

        for elem in self.data:
            print(elem)
            template = Template(url=elem["template-url"], 
                                id= elem["template-id"], 
                                info= elem["info"], 
                                category= elem["type"])
            
            vulnerability = Vulnerability(
                id= elem["info"]["classification"]["cve-id"],
                cvss= elem["info"]["classification"]["cvss-score"],
                where_vulnerability= elem["matched-at"],
                description= elem["info"]["description"],
                severity= elem["info"]["severity"],
                identification_date= elem["timestamp"],
                type_vulnerability= elem["type"],
                requirements= elem["info"]["remediation"],
                tool= "Engine DAST",
                is_excluded= False
                )
            vulnerability_list = []
            vulnerability_list.append(vulnerability)
            self.resultScans.append(ResultScan(
                template= template, 
                target= elem["host"], 
                vulnerabilities= vulnerability_list)
                )

    def get_list_vulnerabilities(self):
        for result_scan in self.resultScans:
            self.vulnerablities_list.extend(result_scan.vulnerabilities)
        return self.vulnerablities_list
    
    def print_table(self, vulnerabilities_without_exclusions_list: 'list[Vulnerability]'):
        vulnerability_table = PrettyTable(["Severity", "ID", "Description", "Where"])

        for vulnerability in vulnerabilities_without_exclusions_list:
            vulnerability_table.add_row(
                [vulnerability.severity, vulnerability.id, vulnerability.description, vulnerability.where_vulnerability])
            
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_table = PrettyTable()
        sorted_table.field_names = vulnerability_table.field_names
        sorted_table.add_rows(sorted(vulnerability_table._rows, key=lambda row: severity_order[row[0]]))

        sorted_table.align["Severity"] = "l"
        sorted_table.align["Description"] = "l"
        sorted_table.align["ID"] = "l"
        sorted_table.align["Where"] = "l"
        sorted_table.set_style(DOUBLE_BORDER)

        if len(sorted_table.rows) > 0:
            print(sorted_table)


if __name__ == '__main__':
    resp = nuclei('https://google-gruyere.appspot.com/432947565819739667646424739745632276508/', ['http'])
    print(resp)