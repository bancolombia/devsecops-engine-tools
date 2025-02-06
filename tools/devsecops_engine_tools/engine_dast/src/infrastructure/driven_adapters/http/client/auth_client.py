from devsecops_engine_tools.engine_dast.src.domain.model.gateways.authentication_gateway import (
    AuthenticationGateway,
)


class AuthClientCredential(AuthenticationGateway):
    def __init__(self, security_auth: dict):
        self.client_id: str = security_auth.get("client_id")
        self.client_secrets: str = security_auth.get("client_secret")

    def get_credentials(self):
        return None