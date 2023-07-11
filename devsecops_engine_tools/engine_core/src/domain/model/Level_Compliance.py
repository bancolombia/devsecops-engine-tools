from dataclasses import dataclass


@dataclass
class LevelCompliance:
    critical: int
    high: int
    medium: int
    low: int
    unknown: int
