from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway import (
    ToolGateway
)

class SecretScan:
    def __init__(self, tool_run: ToolGateway):
        self.tool_run = tool_run
    
    def create_exclude_file(self):
        return self.tool_run.create_exclude_file()
    
    def process(self, exclude_path):
        return self.tool_run.run_tool(exclude_path)