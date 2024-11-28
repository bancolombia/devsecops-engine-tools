import dataclasses
from typing import List
from devsecops_engine_tools.engine_utilities.utils.dataclass_classmethod import FromDictMixin


@dataclasses.dataclass
class Component(FromDictMixin):
    id: int = 0
    name: str = ""
    version: str = ""
    date: str = ""
    Component_id: int = 0


@dataclasses.dataclass
class ComponentList(FromDictMixin):
    count: int = 0
    next = None
    previous = None
    results: List[Component] = dataclasses.field(default_factory=list)
