from dataclasses import dataclass
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold

@dataclass
class InputCore:
    totalized_exclusions: "list[Exclusions]"
    threshold_defined: Threshold
    path_file_results: str
    custom_message_break_build: str
    scope_pipeline: str
    scope_service: str
    stage_pipeline: str
