# jwt_service.py
import jwt


class JWTService:
    BAD_JWT_ALG = ["none", "ES256", "ES384", "ES512"]
    BAD_JWS_ALG = ["none", "ES256", "ES384", "ES512"]
    GOOD_JWE_ALG = ["dir", "RSA-OAEP", "RSA-OAEP-256"]
    GOOD_JWE_ENC = ["A256GCM"]

    def downgrade(self, token):
        newtoken = False
        alg = jwt.get_unverified_header()["alg"]
        data = jwt.decode(token, options={"verify_signature": False})

        if alg == "HS256":
            newtoken = jwt.encode(data, "", algorithm=None)
        return newtoken

    def send_req_downgrade(
        self, agent, natural_response=None, url="", token="", params=None, data=None
    ):
        """Send downgraded JWT token in request using agent"""

        is_vulnerable = False
        message_downgrade = "Downgrade de JWT fallido"

        if natural_response is None:
            agent.auth_bearer(token)
            if data is None:
                natural_response = agent.get(url, params)
            else:
                natural_response = agent.post(url, params)

        agent.auth_bearer(token)
        bad_token = self.downgrade(token)

        if bad_token:
            bad_response = agent.get(url, params)
        else:
            bad_response = agent.post(url, data)
        if natural_response.status_code == bad_response.status_code:
            if natural_response.txt == bad_response.text:
                is_vulnerable = True
                message_downgrade = "Downgrade de JWT exitoso"

        return ("JWT token", "ENGINE_JWT_004", is_vulnerable, message_downgrade, token)

    def check_token(self, token):
        "Verify if token is JWT, JWS or JWE"

        result = ("JWT token", "ENGINE_JWT_001", True, "Algortimo: Default", token)

        hed = jwt.get_unverified_header()

        if "enc" in hed.keys():
            result = self.verify_jwe(token)
        elif "typ" in hed.keys():
            result = self.verify_jwt_alg(token)
        else:
            result = self.verify_jws_alg(token)

        return result

    def verify_jwt_alg(self, token):
        "Evaluate JSON Web token's algorithm"

        is_vulnerable = False
        alg = jwt.get_unverified_header(token)["alg"]

        if alg in self.BAD_JWT_ALG:
            is_vulnerable = True

        return (
            "JWT token",
            "ENGINE_JWT_001",
            is_vulnerable,
            "Algortimo: " + alg,
            token,
        )

    def verify_jws_alg(self, token):
        """Evaluate JSON Web signature's algorithm"""

        is_vulnerable = False
        alg = jwt.get_unverified_header(token)["alg"]

        if alg in self.BAD_JWS_ALG:
            is_vulnerable = True

        return (
            "JWS Token",
            "ENGINE_JWT_002",
            is_vulnerable,
            "Algortimo: " + alg,
            token,
        )

    def verify_jwe(self, token):
        """Evaluate JSON Web encryption's algorithm"""

        msg = ""
        is_vulnerable = True
        enc = jwt.get_unverified_header(token)["enc"]
        alg = jwt.get_unverified_header(token)["alg"]

        if enc in self.GOOD_JWE_ENC:
            if alg in self.GOOD_JWE_ALG:
                is_vulnerable = False
                msg = "Algoritmo: " + alg + " | Cifrado: " + enc
            else:
                msg = "Algoritmo: " + alg
        else:
            msg = "Cifrado: " + enc

        return ("JWE Token", "ENGINE_JWT_003", is_vulnerable, msg, token)
