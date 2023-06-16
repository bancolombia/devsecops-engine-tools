import dataclasses
from typing import List
from devsecops_lib.helper.dataclass_classmethod import FromDictMixin
from devsecops_lib.vultracker.domain.models.scan_configuration import ScanConfiguration


@dataclasses.dataclass
class ScanConfigurationList(FromDictMixin):
    count: int = 2
    next = None
    previous = None
    results: List[ScanConfiguration] = dataclasses.field(default_factory=list)
