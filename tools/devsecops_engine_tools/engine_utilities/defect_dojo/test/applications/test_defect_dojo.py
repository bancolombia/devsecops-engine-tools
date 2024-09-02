from unittest.mock import patch
from devsecops_engine_tools.engine_utilities.defect_dojo.applications.defect_dojo import (
    DefectDojo,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import (
    ImportScanRequest,
)


@patch(
    "devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.import_scan.ImportScanUserCase.execute"
)
def test_send_import_scan(mock_execute):
    mock_execute.return_value = {"url": "ok"}

    request = ImportScanRequest()
    response = DefectDojo.send_import_scan(request)
    assert response == {"url": "ok"}
