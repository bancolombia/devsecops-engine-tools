from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.gateway_deserealizator import (
    DeseralizatorGateway
)

class DeserializeTool:
    def __init__(self, tool_run: DeseralizatorGateway):
        self.tool_run = tool_run
    
    def get_list_vulnerability(self, results_scan_list: list):
        return self.tool_run.get_list_vulnerability(results_scan_list)
    
    def get_where_correctly(self, results_scan_list: any):
        return self.tool_run.get_where_correctly(results_scan_list)