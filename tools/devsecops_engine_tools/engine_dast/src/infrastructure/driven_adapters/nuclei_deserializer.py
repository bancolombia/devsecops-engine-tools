from devsecops_engine_tools.engine_dast.src.domain.model.Scan import Scan
from datetime import datetime

class NucleiDesealizator:
    def __init__(self, json_data, environment=None):
        self.scan = Scan(datetime.now(), "Nuclei", json_data)
    
