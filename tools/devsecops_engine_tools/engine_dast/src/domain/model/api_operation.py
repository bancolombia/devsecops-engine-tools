from devsecops_engine_tools.engine_dast.src.domain.model.gateways.authentication_gateway import (
    AuthenticationGateway
)
class ApiOperation():
    def __init__(self, operation, authentication_gateway):
        self.authentication_gateway: AuthenticationGateway = authentication_gateway
        self.data: dict = operation
        self.credentials = ("auth_header", "token")

    def authenticate(self):
        self.credentials = self.authentication_gateway.get_credentials()
        if self.credentials is not None:
            self.data["operation"]["headers"][f'{self.credentials[0]}'] = f'{self.credentials[1]}'
