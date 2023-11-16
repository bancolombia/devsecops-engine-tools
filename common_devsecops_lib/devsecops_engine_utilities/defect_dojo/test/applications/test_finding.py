import inspect
from devsecops_engine_utilities.defect_dojo.applications.finding import Finding
from devsecops_engine_utilities.utils.session_manager import SessionManager


def test_close_finding():
    session = SessionManager(token="test_token8643f700137f71c15f8980", host="http://localhost:8000/")
    assert session._token == "test_token8643f700137f71c15f8980"
    assert session._host == "http://localhost:8000/"
    assert hasattr(Finding, "close_finding")
    # validate the existence of the method and its parameters
    firm = inspect.signature(Finding.close_finding)
    parameter = [name for name, parameter in firm.parameters.items()]
    assert "session" in parameter
    assert "request" in parameter
