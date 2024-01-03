from dataclasses import dataclass


@dataclass
class Template:
    id: str
    info: dict
    category: str
