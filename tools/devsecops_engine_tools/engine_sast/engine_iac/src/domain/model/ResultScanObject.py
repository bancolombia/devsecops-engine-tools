from dataclasses import dataclass
from tools.devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.LevelCompliance import LevelCompliance


@dataclass
class ResultScanObject:
    results_scan_list: list
    exclusions_all: dict
    exclusions_scope: dict
    rules_scaned : dict
    scope_pipeline: str
    level_compliance: LevelCompliance
