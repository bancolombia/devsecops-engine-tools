from dataclasses import dataclass

@dataclass
class ContextDependencies:
    file_name: str
    file_path: str
    sha1: str
    sha256: str
    vendor: str
    product: str
    version: str
    where: str
    tool: str