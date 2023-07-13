import dataclasses
from typing import List
from devsecops_engine_utilities.utils.dataclass_classmethod import FromDictMixin
from devsecops_engine_utilities.defect_dojo.domain.models.scan_configuration import ScanConfiguration


@dataclasses.dataclass
class ScanConfigurationList(FromDictMixin):
    count: int = 2
    next = None
    previous = None
    results: List[ScanConfiguration] = dataclasses.field(default_factory=list)
