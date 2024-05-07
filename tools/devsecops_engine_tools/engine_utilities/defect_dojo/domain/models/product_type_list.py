import dataclasses
from typing import List
from devsecops_engine_tools.engine_utilities.utils.dataclass_classmethod import FromDictMixin
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product_type import ProductType


@dataclasses.dataclass
class ProductTypeList(FromDictMixin):
    count: int = 0
    next = None
    previous = None
    results: List[ProductType] = dataclasses.field(default_factory=list)
    prefetch = None
