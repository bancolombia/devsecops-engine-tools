from devsecops_engine_tools.engine_utilities.utils.utils import Utils

def test_configurate_external_checks_git():
        json_data = {
            "SEARCH_PATTERN": ["AW", "NU"],
            "IGNORE_SEARCH_PATTERN": ["test"],
            "MESSAGE_INFO_ENGINE_IAC": "message test",
            "EXCLUSIONS_PATH": "Exclusions.json",
            "UPDATE_SERVICE_WITH_FILE_NAME_CFT": "false",
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 10,
                    "High": 3,
                    "Medium": 20,
                    "Low": 30,
                },
                "COMPLIANCE": {"Critical": 4},
            },
            "CHECKOV": {
                "VERSION": "2.3.296",
                "USE_EXTERNAL_CHECKS_GIT": "True",
                "EXTERNAL_CHECKS_GIT": "rules",
                "EXTERNAL_GIT_SSH_HOST": "github",
                "EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT": "fingerprint",
                "USE_EXTERNAL_CHECKS_DIR": "False",
                "EXTERNAL_DIR_OWNER": "test",
                "EXTERNAL_DIR_REPOSITORY": "repository",
                "EXTERNAL_DIR_ASSET_NAME": "rules",
                "RULES": "",
                "APP_ID_GITHUB": "app_id",
                "INSTALATION_ID_GITHUB": "installation_id"
            },
        }


        util = Utils()
        result = util.configurate_external_checks(
            "checkov",json_data, None, "github_token:12234234"
        )

        assert result is None

        
def test_configurate_external_checks_dir():
    json_data = {
        "SEARCH_PATTERN": ["AW", "NU"],
        "IGNORE_SEARCH_PATTERN": [
            "test",
        ],
        "MESSAGE_INFO_ENGINE_IAC": "message test",
        "EXCLUSIONS_PATH": "Exclusions.json",
        "UPDATE_SERVICE_WITH_FILE_NAME_CFT": "false",
        "THRESHOLD": {
            "VULNERABILITY": {
                "Critical": 10,
                "High": 3,
                "Medium": 20,
                "Low": 30,
            },
            "COMPLIANCE": {"Critical": 4},
        },
        "CHECKOV": {
            "VERSION": "2.3.296",
            "USE_EXTERNAL_CHECKS_GIT": "False",
            "EXTERNAL_CHECKS_GIT": "rules",
            "EXTERNAL_GIT_SSH_HOST": "github",
            "EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT": "fingerprint",
            "USE_EXTERNAL_CHECKS_DIR": "True",
            "EXTERNAL_DIR_OWNER": "test",
            "EXTERNAL_DIR_REPOSITORY": "repository",
            "EXTERNAL_DIR_ASSET_NAME": "rules",
            "RULES": "",
            "APP_ID_GITHUB": "app_id",
            "INSTALATION_ID_GITHUB": "installation_id"
        },
    }


    util = Utils()
    result = util.configurate_external_checks("checkov",json_data,None, "ssh:2231231:123123")

    assert result is None
