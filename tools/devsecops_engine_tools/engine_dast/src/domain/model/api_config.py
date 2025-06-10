from typing import List, Optional
from devsecops_engine_tools.engine_dast.src.domain.model.api_operation import ApiOperation

class ApiConfig():
    def __init__(self, api_data: dict):
        try:
            self.target_type: str = "API"
            self.endpoint: str = api_data["endpoint"]
            self.operations: "List[ApiOperation]" = api_data["operations"]
            self.concurrency: Optional[int] = None
            self.rate_limit: Optional[int] = api_data.get("rate_limit", 150)
            self.response_size: Optional[int] = None
            self.bulk_size: Optional[int] = None
            self.timeout: Optional[int] = None

        except KeyError:
            raise KeyError("Missing configuration, validate the endpoint and every single operation")