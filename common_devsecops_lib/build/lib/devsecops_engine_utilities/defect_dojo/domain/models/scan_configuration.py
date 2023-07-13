import dataclasses
from devsecops_engine_utilities.utils.dataclass_classmethod import FromDictMixin


@dataclasses.dataclass
class ScanConfiguration(FromDictMixin):
    id: int = 0
    service_key_1: str = ""
    service_key_2: str = ""
    service_key_3: str = ""
    product: int = 0
    tool_configuration: int = 0
