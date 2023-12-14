from dataclasses import dataclass


@dataclass
class InputCore:
    totalized_exclusions: list
    level_compliance_defined: dict
    path_file_results: str
    custom_message_break_build: str
    scope_pipeline: str
