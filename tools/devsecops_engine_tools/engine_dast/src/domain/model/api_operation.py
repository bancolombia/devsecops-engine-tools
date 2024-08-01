class ApiOperation():
    def __init__(self, operation, authentication_gateway):
        self.authentication_gateway = authentication_gateway
        self.data = operation
        self.credentials = ("auth_header", "token")

    def authenticate(self):
        self.credentials = self.authentication_gateway.get_credentials()
        if self.credentials is not None:
            self.data["operation"]["headers"][f'{self.credentials[0]}'] = f'{self.credentials[1]}'
