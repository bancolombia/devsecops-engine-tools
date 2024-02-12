config_site = """{
    "endpoint": "https://seguros-qa-voluntarios.apps.ambientesbc.com/",
    "security_auth": {
        "type": "oauth",
        "grant_type": "resource_owner",
        "scope": "User.Read openid profile offline_access",
        "headers": {
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json"
        },
        "cookie_session": {
            "path": "/savesession",
            "method": "post",
            "headers": {
                "content-type": "application/x-www-form-urlencoded",
                "accept": "application/json",
                "Authorization": "Bearer access_token"
            }
        }
    }
}
"""
