from devsecops_engine_tools.engine_utilities.utils.utils import Utils
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold

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


def test_update_threshold_by_pattern_search_with_only_tool_exclusions():
    """
    A BY_PATTERN_SEARCH entry that only defines tool exclusions (no THRESHOLD)
    must not raise an error and should keep the default threshold.
    """
    threshold = Threshold(
        {
            "VULNERABILITY": {"Critical": 1, "High": 1, "Medium": 1, "Low": 1},
            "COMPLIANCE": {"Critical": 1},
        }
    )
    exclusions_data = {
        "BY_PATTERN_SEARCH": {
            ".*_Repository_Test": {
                "XRAY": [{"id": "XRAY-522015", "where": "all"}],
            }
        }
    }

    result = Utils.update_threshold(
        Utils(), threshold, exclusions_data, "my_Repository_Test"
    )

    assert result.name == "default"


def test_update_threshold_by_pattern_search_with_threshold():
    threshold = Threshold(
        {
            "VULNERABILITY": {"Critical": 1, "High": 1, "Medium": 1, "Low": 1},
            "COMPLIANCE": {"Critical": 1},
        }
    )
    exclusions_data = {
        "BY_PATTERN_SEARCH": {
            ".*_Repository_Test": {
                "THRESHOLD": {"VULNERABILITY": {"Critical": 99}},
                "XRAY": [{"id": "XRAY-522015", "where": "all"}],
            }
        }
    }

    result = Utils.update_threshold(
        Utils(), threshold, exclusions_data, "my_Repository_Test"
    )

    assert result.vulnerability.critical == 99

