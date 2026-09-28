import dataclasses
from devsecops_engine_tools.engine_utilities.utils.dataclass_classmethod import FromDictMixin


@dataclasses.dataclass
class LongRiskAcceptance(FromDictMixin):
    id: int = 0
    name: str = ""
    created: str = ""
    expiration_date: str = ""
