from dataclasses import dataclass
from devsecops_engine_tools.engine_dast.src.domain.model.Template import Template
from devsecops_engine_tools.engine_dast.src.domain.model.ResultScan import ResultScan


@dataclass
class Scan:
    date: str
    scan_type: str
    data: list[dict]
