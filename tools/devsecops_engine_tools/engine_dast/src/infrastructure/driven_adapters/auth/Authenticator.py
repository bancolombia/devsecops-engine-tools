class Authenticator:
    def __init__(self, target_config, data_config_cli):
        self.target_config = target_config
        self.data_config_cli = data_config_cli

    def get_authentication(self):
        if self.target_config["security_auth"]["type"] == "basic":
            return self.basic_authentication()
        elif self.target_config["security_auth"]["type"] == "oauth":
            return self.oauth_authentication()
        elif self.target_config["security_auth"]["type"] == "cookie":
            return self.cookie_authentication()
        else:
            return None
