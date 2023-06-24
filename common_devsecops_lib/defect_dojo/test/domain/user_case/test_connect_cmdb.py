import pytest
from unittest.mock import MagicMock
from defect_dojo.domain.models.cmdb import Cmdb
from defect_dojo.domain.serializers.import_scan import ImportScanSerializer
from defect_dojo.infraestructure.driver_adapters.cmdb import (
    CmdbRestConsumer,
)
from defect_dojo.domain.request_objects.import_scan import (
    ImportScanRequest,
)
from helper.validation_error import ValidationError
from defect_dojo.domain.user_case.cmdb import CmdbUserCase


def import_scan_request_instance(par_scan_type) -> ImportScanRequest:
    request = ImportScanRequest(
        product_name="test product name",
        token="123456789",
        host="https://test/test.com",
        token_vultracker="123456789101212",
        host_vultracker="http://localhost:8000",
        scan_type=par_scan_type,
        engagement_name="test engagement name",
        file="common_devsecops_lib.defect_dojo/tests/files/xray_scan.json",
        tags="evc",
    )
    return request

def get_cmdb_instance():
    mock_rest_consumer_cmdb = MagicMock(spec=CmdbRestConsumer)
    mock_rest_consumer_cmdb.get_product_info.return_value = Cmdb(
        product_type_name="type name test",
        product_name="product name test",
        tag_product="tag product test",
        product_description="description test",
        codigo_app="nu0429001",
    )
    return mock_rest_consumer_cmdb
    

@pytest.mark.parametrize(
    "engagement_name",
    [("NU0429001_Acceptance Tests"), ("NU0429001_Acceptance Tests23")]
)
def test_execute(engagement_name):
    mock_rest_consumer_cmdb = get_cmdb_instance()
    request = {
        "product_name": "test product name",
        "token": "123456789",
        "host": "http://localhost:8000",
        "token_vultracker": "123456789101212",
        "host_vultracker": "http://localhost:8000",
        "scan_type": "JFrog Xray Scan",
        "engagement_name": engagement_name,
        "file": "defect_dojo/test/files/xray_scan.json",
        "tags": "evc",
    }
    request: ImportScanRequest = ImportScanSerializer().load(request)
    rc = mock_rest_consumer_cmdb(
        request, token="91qewuro9quowedafj", host="https://localhost:8000"
    )
    uc = CmdbUserCase(rest_consumer_cmdb=rc)
    response = uc.execute(request)
    assert response.scan_type == "JFrog Xray Scan"
    assert response.code_app == "nu0429001"


@pytest.mark.parametrize(
    "engagement_name",
    [("error"), ("nu12212error")]
)
def test_get_code_app(engagement_name):
    uc = CmdbUserCase(rest_consumer_cmdb=None)
    with pytest.raises(ValidationError):
        uc.get_code_app(engagement_name)
