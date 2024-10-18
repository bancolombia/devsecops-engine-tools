from time import (
    time
)
from secrets import (
    token_hex
)
from authlib.jose import (
    jwt
)
from devsecops_engine_tools.engine_dast.src.domain.model.gateways.authentication_gateway import (
    AuthenticationGateway,
)


class JwtObject(AuthenticationGateway):
    def __init__(self, security_auth: dict):
        self.type = "jwt"
        self.private_key: str = security_auth.get("jwt_private_key")
        self.algorithm: str = security_auth.get("jwt_algorithm")
        self.iss: str = security_auth.get("jwt_iss")
        self.sum: str = security_auth.get("jwt_sum")
        self.aud: str = security_auth.get("jwt_aud")
        self.iat: float = time()
        self.exp: float = self.iat + 60 * 60
        self.nonce = token_hex(10)
        self.payload: dict = {}
        self.header: dict = {}
        self.jwt_token: str = ""
        self.header_name: str = security_auth.get("jwt_header_name")
        self.init_header()
        self.init_payload()

    def init_header(self) -> None:
        self.header: dict = {"alg": self.algorithm}

    def init_payload(self) -> dict:
        self.payload: dict = {
            "iss": self.iss,
            "sum": self.sum,
            "aud": self.aud,
            "exp": self.exp,
            "iat": self.iat,
            "nonce": self.nonce,
        }
        return self.payload

    def get_credentials(self) -> tuple:
        """
        Generates JWT using a file with the configuration

        Returns:

        tuple: header and jwt

        """
        self.private_key = (
            self.private_key.replace(" ", "\n")
            .replace("-----BEGIN\nPRIVATE\nKEY-----", "-----BEGIN PRIVATE KEY-----")
            .replace("-----END\nPRIVATE\nKEY-----", "-----END PRIVATE KEY-----")
        )
        self.jwt_token = jwt.encode(self.header, self.payload, self.private_key).decode(
            "utf-8"
        )
        return self.header_name, self.jwt_token