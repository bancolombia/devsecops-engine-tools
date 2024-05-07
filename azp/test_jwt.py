# jwt_token.py
from authlib.jose import jwt
from dataclasses import dataclass
from tools.devsecops_engine_tools.engine_dast.src.domain.model.gateways.token_technology import (
    Token,
)
import time
import secrets


class JwtObject:
    def init_header(self):
        self.header = {"alg": self.algorithm}

    def init_payload(self):
        self.payload = {
            "iss": self.iss,
            "sum": self.sum,
            "aud": self.aud,
            "exp": self.exp,
            "iat": self.iat,
            "nonce": self.nonce,
        }
        return self.payload

    def generate_token(self):
        self.private_key = (
            self.private_key.replace(" ", "\n")
            .replace("-----BEGIN\nPRIVATE\nKEY-----", "-----BEGIN PRIVATE KEY-----")
            .replace("-----END\nPRIVATE\nKEY-----", "-----END PRIVATE KEY-----")
        )
        self.jwt_token = jwt.encode(self.header, self.payload, self.private_key).decode(
            "utf-8"
        )
        return self.jwt_token

    def __init__(self, private_key, algorithm, iss, check_sum, aud, header_name):
        self.private_key = private_key
        self.algorithm = algorithm
        self.iss = iss
        self.sum = check_sum
        self.aud = aud
        self.iat = time.time()
        self.exp = self.iat + 60 * 60
        self.nonce = secrets.token_hex(10)
        self.payload = None
        self.header = None
        self.jwt_token = None
        self.header_name = header_name

if __name__ == "__main__":
    private_key = ""
    algorithm = "RS256"
    iss = "PRODUCTORCONSUMIDOR"
    check_sum = "5d09e768-4bbc-4614-9b30-d9abfcb663a7"
    aud = "APIGateway_LAN"
    payload = ""
    header = ""
    header_name = "json-web-token"

    jwt_object = JwtObject(private_key, algorithm, iss, check_sum, aud, header_name)
    jwt_object.init_header()
    jwt_object.init_payload()
    print(jwt_object.generate_token())
# https://dev.azure.com/PNFEngineTest/Pruebas_PNF_Engine/_releaseProgress?releaseId=437&environmentId=1175&_a=release-environment-variables 
# sacar variable jwt_private_key del pipeline y poner en la variable local private_key situada arriba
