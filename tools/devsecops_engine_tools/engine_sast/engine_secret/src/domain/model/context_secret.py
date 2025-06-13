from dataclasses import dataclass

@dataclass
class ContextSecret:
    id: str
    severity: str
    type: str
    where: str
    description: str
    module: str
    tool: str