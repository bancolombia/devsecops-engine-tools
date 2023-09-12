from dataclasses import dataclass
from devsecops_engine_tools.engine_dast.src.domain.model.Vulnerability import Vulnerability
from devsecops_engine_tools.engine_dast.src.domain.model.Template import Template

@dataclass
class ResultScan:
    template: Template
    target: str
    vulnerabilities: list[Vulnerability]
