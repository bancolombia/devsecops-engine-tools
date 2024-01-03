class JWTAuthenticator:
    def get_access_token(self):
        return self.config["token"]

    def jwt_data(self):
        return self.config["jwt_data"]
