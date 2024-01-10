from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway import (
    ToolGateway
)

class SecretScan:
    def __init__(self, tool_run: ToolGateway):
        self.tool_run = tool_run
    
    def process(self):
        return self.tool_run.run_tool()