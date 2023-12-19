from dataclasses import dataclass
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_core.src.domain.model.level_compliance import LevelCompliance

@dataclass
class InputCore:
    totalized_exclusions: "list[Exclusions]"
    level_compliance_defined: LevelCompliance
    path_file_results: str
    custom_message_break_build: str
    scope_pipeline: str
