from dataclasses import dataclass

from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model import LevelCompliance


@dataclass
class ResultScanObject:
    results_scan_list: list
    level_compliance: LevelCompliance
