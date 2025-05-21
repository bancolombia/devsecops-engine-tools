from dataclasses import dataclass


@dataclass
class ContextIac:
    id: str
    check_name: str
    check_class: str
    severity: str
    where: str
    resource: str
    description: str
    module: str
    tool: str
