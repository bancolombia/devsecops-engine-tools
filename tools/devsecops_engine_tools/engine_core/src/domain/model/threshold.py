from devsecops_engine_tools.engine_core.src.domain.model.level_vulnerability import (
    LevelVulnerability,
)
from devsecops_engine_tools.engine_core.src.domain.model.level_compliance import (
    LevelCompliance,
)
from devsecops_engine_tools.engine_core.src.domain.model.custom_level_vulnerability import (
    CustomLevelVulnerability,
)

class Threshold:
    def __init__(self, data):
        self.vulnerability = LevelVulnerability(data.get("VULNERABILITY"))
        self.compliance = LevelCompliance(data.get("COMPLIANCE"))
        self.cve = data.get("CVE",[])
        self.custom_vulnerability = CustomLevelVulnerability(data.get("CUSTOM_VULNERABILITY")) if data.get("CUSTOM_VULNERABILITY") else None
