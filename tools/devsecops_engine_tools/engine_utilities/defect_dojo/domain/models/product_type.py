import dataclasses
from typing import List
from devsecops_engine_tools.engine_utilities.utils.dataclass_classmethod import FromDictMixin


@dataclasses.dataclass
class ProductType(FromDictMixin):
    id: int = 0
    name: str = ""
    description: str = ""
    critical_product: bool = None
    key_product: bool = None
    updated: str = ""
    created: str = ""
    members: List[int] = dataclasses.field(default_factory=list)
    authorization_groups: List[None] = dataclasses.field(default_factory=list)
