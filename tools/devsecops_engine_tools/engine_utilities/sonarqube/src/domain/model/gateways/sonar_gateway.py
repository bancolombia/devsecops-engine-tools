from abc import (
    ABCMeta,
    abstractmethod
)

class SonarGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_project_keys(
        self,
        pipeline_name: str
    ):
        "get sonar project keys"

    @abstractmethod
    def parse_project_key(
        self,
        file_path: str
    ):
        "find project key in metadata file"

    @abstractmethod
    def create_task_report_from_string(
        self,
        file_content: str
    ):
        "make dict from metadata file"

    @abstractmethod
    def filter_by_sonarqube_tag(
        self,
        findings: list
    ):
        "search for sonar findings"
    
    @abstractmethod
    def change_finding_status(
        self,
        sonar_url: str,
        sonar_token: str,
        endpoint: str,
        data: dict,
        finding_type: str,
        sonar_max_retry: int
    ):
        "use API to change vulnerabilities state in sonar"

    @abstractmethod
    def get_findings(
        self,
        sonar_url: str,
        sonar_token: str,
        endpoint: str,
        params: dict,
        finding_type: str,
        sonar_max_retry: int
    ):
        "use API to get project findings in sonar"

    @abstractmethod
    def search_finding_by_id(
        self,
        findings: list,
        finding_id: str
    ):
        "search a finding by id"