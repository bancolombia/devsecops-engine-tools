import dataclasses
from typing import List
from devsecops_engine_tools.engine_utilities.utils.dataclass_classmethod import FromDictMixin


@dataclasses.dataclass
class FindingExclusion(FromDictMixin):
    uuid: str = ""
    unique_id_from_tool: str = ""
    type: str = ""
    create_date: str = ""
    expiration_date: str = ""


@dataclasses.dataclass
class FindingExclusionList(FromDictMixin):
    count: int = 0
    next = None
    previous = None
    results: List[FindingExclusion] = dataclasses.field(default_factory=list)
