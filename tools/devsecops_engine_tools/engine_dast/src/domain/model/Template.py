from dataclasses import dataclass

@dataclass
class Template:
    url: str
    id: str
    info: dict
    category: str