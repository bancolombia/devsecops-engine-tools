import dataclasses
from typing import List, Dict, Optional
from devsecops_engine_tools.engine_utilities.utils.dataclass_classmethod import FromDictMixin
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product import Product
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product_type import ProductType


@dataclasses.dataclass
class Prefetch(FromDictMixin):
    prod_type: Dict[str, ProductType] = dataclasses.field(default_factory=dict)

@dataclasses.dataclass
class ProductList(FromDictMixin):
    count: int = 0
    next: Optional[str] = None
    previous: Optional[str] = None
    results: List[Product] = dataclasses.field(default_factory=list)
    prefetch: Optional[Prefetch] = None
