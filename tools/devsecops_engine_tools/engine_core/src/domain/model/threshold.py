from devsecops_engine_tools.engine_core.src.domain.model.level_vulnerability import (
    LevelVulnerability,
)
from devsecops_engine_tools.engine_core.src.domain.model.level_compliance import (
    LevelCompliance,
)

class Threshold:
    def __init__(self, data):
        self.vulnerability = LevelVulnerability(data.get("VULNERABILITY"))
        self.compliance = LevelCompliance(data.get("COMPLIANCE"))
        self.cve = data.get("CVE",[])
        self.name = data.get("NAME", "default")
        self.quality_vulnerability_management = data.get("QUALITY_VULNERABILITY_MANAGEMENT") if data.get("QUALITY_VULNERABILITY_MANAGEMENT") else None
