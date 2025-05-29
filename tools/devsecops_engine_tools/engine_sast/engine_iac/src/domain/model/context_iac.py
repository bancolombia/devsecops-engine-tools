from dataclasses import dataclass

@dataclass
class ContextIac:
    id: str
    check_class: str
    severity: str
    where: str
    fix_key: str
    resource: str
    description: str
    module: str
    tool: str