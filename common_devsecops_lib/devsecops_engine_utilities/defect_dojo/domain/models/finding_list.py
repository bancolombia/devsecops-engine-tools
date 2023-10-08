import dataclasses
from typing import List
from devsecops_engine_utilities.utils.dataclass_classmethod import FromDictMixin
from devsecops_engine_utilities.defect_dojo.domain.models.finding import Finding


@dataclasses.dataclass
class FindingList(FromDictMixin):
    count: int = 0
    next = None
    previous = None
    results: List[Finding] = dataclasses.field(default_factory=list)
    prefetch = None
