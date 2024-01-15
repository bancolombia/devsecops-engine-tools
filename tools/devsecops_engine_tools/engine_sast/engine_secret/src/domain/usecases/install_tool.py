from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_install_gateway import (
    ToolInstallGateway
)

class InstallTool:
    def __init__(self, tool_run: ToolInstallGateway):
        self.tool_run = tool_run
    
    def check_version_tool(self):
        return self.tool_run.check_tool()