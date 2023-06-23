import dataclasses
from typing import List
from helper.dataclass_classmethod import FromDictMixin
from defect_dojo.domain.models.product import Product


@dataclasses.dataclass
class ProductList(FromDictMixin):
    count: int = 0
    next = None
    previous = None
    results: List[Product] = dataclasses.field(default_factory=list)
