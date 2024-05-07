
class ApiOperation():
    def __init__(self, operation, authentication_gateway):
        self.authentication_gateway = authentication_gateway
        self.data = operation
        self.token = None

    def authenticate(self):
        self.token = self.authentication_gateway.get_credentials()
        return self.token
