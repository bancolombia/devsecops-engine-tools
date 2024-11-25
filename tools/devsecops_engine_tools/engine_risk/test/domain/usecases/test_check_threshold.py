from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_risk.src.domain.usecases.check_threshold import (
    CheckThreshold,
)

def test_process_pipeline_name():
    pipeline_name = "pipeline_name_test"
    threshold = {
        "REMEDIATION_RATE": 1,
            "RISK_SCORE": 1,
            "TAG_MAX_AGE": 1
    }
    risk_exclusions = {
        "pipeline_name_test": {
            "THRESHOLD": {
                "REMEDIATION_RATE": 2,
                "RISK_SCORE": 2,
                "TAG_MAX_AGE": 2
            }
        }
    }
    expected_threshold = {
        "REMEDIATION_RATE": 2,
        "RISK_SCORE": 2,
        "TAG_MAX_AGE": 2
    }

    check_threshold = CheckThreshold(pipeline_name, threshold, risk_exclusions)

    assert check_threshold.process() == expected_threshold

def test_process_pattern():
    pipeline_name = "pipeline_name_test"
    threshold = {
        "REMEDIATION_RATE": 1,
            "RISK_SCORE": 1,
            "TAG_MAX_AGE": 1
    }
    risk_exclusions = {
        "BY_PATTERN_SEARCH": {
            ".*(pipeline_name).*": {
                "THRESHOLD": {
                    "REMEDIATION_RATE": 2,
                    "RISK_SCORE": 2,
                    "TAG_MAX_AGE": 2
                }
            }
        }
    }
    expected_threshold = {
        "REMEDIATION_RATE": 2,
        "RISK_SCORE": 2,
        "TAG_MAX_AGE": 2
    }

    check_threshold = CheckThreshold(pipeline_name, threshold, risk_exclusions)

    assert check_threshold.process() == expected_threshold

def test_process_default():
    pipeline_name = "pipeline_name_test"
    threshold = {
        "REMEDIATION_RATE": 1,
            "RISK_SCORE": 1,
            "TAG_MAX_AGE": 1
    }
    risk_exclusions = {
        "THRESHOLD": {
            "REMEDIATION_RATE": 2,
            "RISK_SCORE": 2,
            "TAG_MAX_AGE": 2
        }
    }
    expected_threshold = {
        "REMEDIATION_RATE": 1,
        "RISK_SCORE": 1,
        "TAG_MAX_AGE": 1
    }

    check_threshold = CheckThreshold(pipeline_name, threshold, risk_exclusions)

    assert check_threshold.process() == expected_threshold