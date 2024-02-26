import pytest
from devsecops_engine_utilities.utils.api_error import ApiError
from devsecops_engine_utilities.settings import DEVSECOPS_ENGINE_UTILITIES_PATH
from unittest.mock import MagicMock
from devsecops_engine_utilities.defect_dojo.domain.models.cmdb import Cmdb
from devsecops_engine_utilities.defect_dojo.domain.serializers.import_scan import ImportScanSerializer
from devsecops_engine_utilities.defect_dojo.infraestructure.driver_adapters.cmdb import (
    CmdbRestConsumer,
)
from devsecops_engine_utilities.defect_dojo.domain.request_objects.import_scan import (
    ImportScanRequest,
)
from devsecops_engine_utilities.azuredevops.infrastructure.azure_devops_api import AzureDevopsApi
from devsecops_engine_utilities.defect_dojo.domain.user_case.cmdb import CmdbUserCase


def import_scan_request_instance(par_scan_type) -> ImportScanRequest:
    request = ImportScanRequest(
        product_name="test product name",
        token="123456789",
        host="https://test/test.com",
        token_defect_dojo="123456789101212",
        host_defect_dojo="http://localhost:8000",
        scan_type=par_scan_type,
        engagement_name="test engagement name",
        file=f"{DEVSECOPS_ENGINE_UTILITIES_PATH}/defect_dojo/tests/files/xray_scan.json",
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
        codigo_app="NU12345",
    )
    return mock_rest_consumer_cmdb


@pytest.mark.parametrize("engagement_name", [("NU12345_Acceptance Tests"), ("NU12345_Acceptance Tests23")])
def test_execute(engagement_name):
    mock_rest_consumer_cmdb = get_cmdb_instance()
    request = {
        "cmdb_mapping": {
            "product_type_name": "nombreevc",
            "product_name": "nombreapp",
            "tag_product": "nombreentorno",
            "product_description": "arearesponsableti",
            "codigo_app": "CodigoApp",
        },
        "organization_url": "https://organizaciont.visualstudio.com/",
        "personal_access_token": "tokenxxxx12354564",
        "product_name": "test product name",
        "repository_id": "repositoryid_or_name_repository",
        "remote_config_path": "/defect_dojo/cmdb_mapping.json",
        "project_remote_config": "Vicepresidencia Servicios de Tecnología",
        "token_cmdb": "123456789",
        "host_cmdb": "http://localhost:8000",
        "expression": "((AUD|AP|CLD|USR|OPS|ASN|AW|NU|EUC|IS))_",
        "token_defect_dojo": "123456789101212",
        "host_defect_dojo": "http://localhost:8000",
        "scan_type": "JFrog Xray Scan",
        "engagement_name": engagement_name,
        "file": f"{DEVSECOPS_ENGINE_UTILITIES_PATH}/defect_dojo/test/files/xray_scan.json",
        "tags": "evc",
    }
    request: ImportScanRequest = ImportScanSerializer().load(request)
    mock_rc = mock_rest_consumer_cmdb(request, token="91qewuro9quowedafj", host="https://localhost:8000")
    # response file contect json
    file_content = [b'{"key": "value"}']
    # mock git client
    mock_git_client = MagicMock()
    mock_git_client.get_item_text.return_value = file_content
    # mock conecction
    mock_connection = MagicMock()
    mock_connection.clients.get_git_client.return_value = mock_git_client
    # mock class azureDevopsApi
    mock_utils_azure = MagicMock(spec=AzureDevopsApi)
    mock_utils_azure.get_azure_connection.return_value = mock_connection
    AzureDevopsApi(
        personal_access_token="asjfdiajf",
        project_remote_config="project remote test",
        organization_url="http://organization_url/",
    )

    uc = CmdbUserCase(
        rest_consumer_cmdb=mock_rc,
        utils_azure=mock_utils_azure,
        expression=r"((AUD|AP|CLD|USR|OPS|ASN|AW|NU|EUC|IS)\d+)",
    )

    response = uc.execute(request)
    assert response.scan_type == "JFrog Xray Scan"
    assert response.code_app == "nu12345"


@pytest.mark.parametrize("engagement_name", [("error"), ("nu12212error")])
def test_get_code_app(engagement_name):
    uc = CmdbUserCase(
        rest_consumer_cmdb=None, utils_azure=None, expression=r"((AUD|AP|CLD|USR|OPS|ASN|AW|NU|EUC|IS)\d+)_"
    )
    with pytest.raises(ApiError):
        uc.get_code_app(engagement_name)
