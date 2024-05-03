import dataclasses
from devsecops_engine_tools.engine_utilities.utils.dataclass_classmethod import FromDictMixin


@dataclasses.dataclass
class Cmdb(FromDictMixin):
    product_type_name: str = ""
    product_name: str = ""
    tag_product: str = ""
    product_description: str = ""
    codigo_app: str = ""
