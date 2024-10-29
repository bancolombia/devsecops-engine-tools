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
    def change_issue_transition(
        self,
        sonar_url: str,
        sonar_token: str,
        issue_id: str,
        transition: str
    ):
        "use API to change vulnerabilities state in sonar"

    @abstractmethod
    def get_vulnerabilities(
        self,
        sonar_url: str,
        sonar_token: str,
        project_key: str
    ):
        "use API to get project vulnerabilities in sonar"

    @abstractmethod
    def find_issue_by_id(
        self,
        issues: dict,
        issue_id: str
    ):
        "find an issue by id"