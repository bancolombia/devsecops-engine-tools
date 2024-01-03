from devsecops_engine_tools.engine_dast.src.domain.model.Scan import Scan
from devsecops_engine_tools.engine_dast.src.domain.model.ResultScan import ResultScan
from devsecops_engine_tools.engine_dast.src.domain.model.Template import Template
from devsecops_engine_tools.engine_dast.src.domain.model.Vulnerability import (
    Vulnerability,
)
from prettytable import PrettyTable, DOUBLE_BORDER


class NucleiProcess:
    def __init__(self, scan: Scan):
        self.data = scan.data
        self.resultScans: list[ResultScan] = []
        self.vulnerablities_list: list[Vulnerability] = []

    def get_template(self, data):
        if "template-id" in data:
            template = Template(
                id=data["template-id"],
                info=data["info"],
                category=data["type"],
            )
            return template
        else:
            return None

    def vulnerability_matcher(self, data):
        type = data["type"]
        if type == "http":
            return self.get_http_vulnerability(data)
        if type == "dns":
            return self.check_dns(data)
        elif type == "ssl":
            return self.check_ssl(data)
        else:
            return self.get_cve_vulnerability(data)
        
    def get_http_vulnerability(self, data):
        if data["info"]:
            if data["info"]["classification"]:
                vulnerability = Vulnerability(
                    id=data["info"]["name"],
                    cwe_id=data["info"]["classification"]["cwe-id"],
                    cvss=data["info"]["classification"].get("cvss-score", 0),
                    where_vulnerability=data["matched-at"],
                    description=data["info"]["description"],
                    severity=data["info"]["severity"],
                    identification_date=data["timestamp"],
                    type_vulnerability=data["type"],
                    requirements="",
                    tool="Engine DAST",
                    is_excluded=False,
                )
        return vulnerability

    def get_cve_vulnerability(self, data):
        if "classification" in data["info"]:
            if data["info"]["classification"]["cve-id"] is not None:
                vulnerability = Vulnerability(
                    id=data.get("info").get("classification").get("cve-id")[0],
                    cwe_id=data["info"]["classification"]["cwe-id"],
                    cvss=data["info"]["classification"]["cvss-score"],
                    where_vulnerability=data["matched-at"],
                    description=data["info"]["description"],
                    severity=data["info"]["severity"],
                    identification_date=data["timestamp"],
                    type_vulnerability=data["type"],
                    requirements=data["info"]["remediation"],
                    tool="Engine DAST",
                    is_excluded=False,
                )
        else:
            vulnerability = Vulnerability(
                id=data.get("info").get("template-id"),
                cwe_id="",
                cvss="",
                requirements="",
                where_vulnerability=data["matched-at"],
                description=data["info"]["description"],
                severity=data["info"]["severity"],
                identification_date=data["timestamp"],
                type_vulnerability=data["type"],
                tool="Engine DAST",
                is_excluded=False,
            )

        return vulnerability

    def check_dns(self, data):
        vulnerability = Vulnerability(
            id=data["info"]["name"],
            cwe_id=None,
            cvss=None,
            where_vulnerability=data["matched-at"],
            description=data["info"]["description"],
            severity=data["info"]["severity"],
            identification_date=data["timestamp"],
            type_vulnerability=data["type"],
            requirements=data["remediation"] if "remediation" in data else None,
            tool="Engine DAST",
            is_excluded=False,
        )
        return vulnerability

    def check_ssl(self, data):
        vulnerability = Vulnerability(
            id=data["info"]["name"],
            cwe_id=None,
            cvss=None,
            where_vulnerability=data["matched-at"],
            description=data["info"]["description"],
            severity=data["info"]["severity"],
            identification_date=data["timestamp"],
            type_vulnerability=data["type"],
            requirements=data["remediation"] if "remediation" in data else None,
            tool="Engine DAST",
            is_excluded=False,
        )
        return vulnerability

    def get_result_scans(self):
        for elem in self.data:
            template = self.get_template(elem)
            if template:
                vulnerability = self.vulnerability_matcher(elem)
                self.resultScans.append(
                    ResultScan(
                        template=template,
                        target=elem["host"],
                        vulnerabilities=[vulnerability],
                    )
                )

    def get_list_vulnerabilities(self):
        if len(self.resultScans) > 0:
            for result_scan in self.resultScans:
                self.vulnerablities_list.extend(result_scan.vulnerabilities)
            return self.vulnerablities_list

    def print_table(
        self, vulnerabilities_without_exclusions_list: "list[Vulnerability]" = []
    ):
        if isinstance(vulnerabilities_without_exclusions_list, list):
            if len(vulnerabilities_without_exclusions_list) > 0:
                vulnerability_table = PrettyTable(
                    ["Severity", "ID", "Description", "Where"]
                )

                for vulnerability in vulnerabilities_without_exclusions_list:
                    vulnerability_table.add_row(
                        [
                            vulnerability.severity,
                            vulnerability.id,
                            vulnerability.description,
                            vulnerability.where_vulnerability,
                        ]
                    )

                severity_order = {
                    "critical": 0,
                    "high": 1,
                    "medium": 2,
                    "low": 3,
                    "info": 4,
                }
                sorted_table = PrettyTable()
                sorted_table.field_names = vulnerability_table.field_names
                sorted_table.add_rows(
                    sorted(
                        vulnerability_table._rows,
                        key=lambda row: severity_order[row[0]],
                    )
                )

                sorted_table.align["Severity"] = "l"
                sorted_table.align["Description"] = "l"
                sorted_table.align["ID"] = "l"
                sorted_table.align["Where"] = "l"
                sorted_table.set_style(DOUBLE_BORDER)

                if len(sorted_table.rows) > 0:
                    print(sorted_table)
        else:
            print("No vulnerabiltiies found")
