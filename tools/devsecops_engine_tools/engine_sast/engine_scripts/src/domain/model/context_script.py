from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ContextScript:
    id: str
    check_name: str
    check_class: str
    severity: str
    where: str
    resource: str
    description: str
    module: str
    tool: str
    priority: Optional[str] = field(default=None)
