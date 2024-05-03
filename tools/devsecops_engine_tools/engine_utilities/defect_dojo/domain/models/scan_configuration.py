import dataclasses
from typing import List
from devsecops_engine_tools.engine_utilities.utils.dataclass_classmethod import FromDictMixin


@dataclasses.dataclass
class ScanConfiguration(FromDictMixin):
    id: int = 0
    service_key_1: str = ""
    service_key_2: str = ""
    service_key_3: str = ""
    product: int = 0
    tool_configuration: int = 0


@dataclasses.dataclass
class ScanConfigurationList(FromDictMixin):
    count: int = 2
    next = None
    previous = None
    results: List[ScanConfiguration] = dataclasses.field(default_factory=list)