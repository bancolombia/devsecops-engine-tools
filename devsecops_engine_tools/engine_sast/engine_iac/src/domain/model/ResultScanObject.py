from dataclasses import dataclass


@dataclass
class ResultScanObject:
    rules_scan_list: list
    exclusions_all: dict
    exclusions_scope: dict
    scope_pipeline: str
