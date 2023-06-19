import dataclasses
from typing import List
from helper.dataclass_classmethod import FromDictMixin
from defect_dojo.domain.models.product_type import ProductType


@dataclasses.dataclass
class ProductTypeList(FromDictMixin):
    count: int = 0
    next = None
    previous = None
    results: List[ProductType] = dataclasses.field(default_factory=list)
    prefetch = None
