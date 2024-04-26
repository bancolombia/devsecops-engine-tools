import pytest
import json
from devsecops_engine_tools.engine_utilities.settings import devsecops_engine_tools.engine_utilities_PATH
from unittest.mock import MagicMock
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product_type_list import ProductTypeList
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.scan_configuration import ScanConfiguration
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product_list import ProductList
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product import Product
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product_type import ProductType
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.engagement import Engagement, EngagementList
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.import_scan import ImportScanRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.product_type import ProductTypeRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.product import ProductRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.scan_configurations import (
    ScanConfigrationRestConsumer,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.engagement import EngagementRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.import_scan import ImportScanUserCase
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager


def import_scan_request_instance(par_scan_type, product_name="test product name", file_name=None) -> ImportScanRequest:
    file = f"{devsecops_engine_tools.engine_utilities_PATH}/defect_dojo/test/files/request_file/{file_name}"
    request = ImportScanRequest(
        product_name=product_name,
        token_cmdb="123456789",
        host_cmdb="https://test/test.com",
        token_defect_dojo="123456789101212",
        host_defect_dojo="http://localhost:8000",
        scan_type=par_scan_type,
        engagement_name="test engagement name",
        file=file,
        tags="evc",
    )
    return request


def test_user_case_creation():
    request = import_scan_request_instance(par_scan_type="Xray scan", file_name="jfrog-xray_on_demand_binary_scan.json")
    assert isinstance(request, ImportScanRequest)
    rest_import_scan = ImportScanRestConsumer(request, SessionManager())
    rest_product_type = ProductTypeRestConsumer(request, SessionManager())
    rest_product = ProductRestConsumer(request, SessionManager())
    rest_scan_configuration = ScanConfigrationRestConsumer(request, SessionManager())
    rest_engagement = EngagementRestConsumer(request, SessionManager())
    uc = ImportScanUserCase(
        rest_import_scan=rest_import_scan,
        rest_product_type=rest_product_type,
        rest_product=rest_product,
        rest_scan_configuration=rest_scan_configuration,
        rest_engagement=rest_engagement,
    )
    assert isinstance(uc, object)
    assert hasattr(uc, "__init__")
    assert hasattr(uc, "execute")


def mock_rest_import_scan(file_path, scan_type=None):
    mock_import_scan = MagicMock()
    with open(f"{devsecops_engine_tools.engine_utilities_PATH}/defect_dojo/test/files/{file_path}", "r") as fp:
        data = json.load(fp)
        if scan_type:
            data["scan_type"] = scan_type
        import_scan_object = ImportScanRequest.from_dict(data)
        assert import_scan_object.scan_type == data["scan_type"]
        assert import_scan_object.product_type_name == data["product_type_name"]
        assert import_scan_object.engagement_name == data["engagement_name"]
        mock_import_scan.import_scan_api.return_value = import_scan_object
        mock_import_scan.import_scan.return_value = import_scan_object
    return mock_import_scan


def mock_rest_product_type(product_type_empty=False):
    mock_rest_product_type = MagicMock()
    products = [
        ProductType(
            id=1,
            name="xray",
            description="test",
            critical_product="flase",
            key_product="false",
            updated="2023-06-08T19:47:54.838512Z",
            created="2023-06-08T19:47:54.838527Z",
        )
    ]
    if product_type_empty:
        mock_rest_product_type.get_product_types.return_value = ProductTypeList(count=1, results=[])
    else:
        mock_rest_product_type.get_product_types.return_value = ProductTypeList(count=1, results=products)
    mock_rest_product_type.post_product_type.return_value = products[0]
    return mock_rest_product_type


def mock_rest_product(result_list_empty=False):
    mock_product = MagicMock()
    product = Product(id=1, name="product name test")
    if result_list_empty:
        products = ProductList(count=1, results=[])
    else:
        products = ProductList(count=1, results=[product])
    mock_product.get_products.return_value = products
    mock_product.post_product.return_value = product
    return mock_product


def mock_rest_engagement(result_list_empty=False):
    if result_list_empty:
        engagements = EngagementList(count=0, results=[])
        return engagements
    mock_engagement = MagicMock()
    engagement = Engagement(id=3, name="name engagement test")
    engagement = EngagementList(count=1, results=[engagement])
    mock_engagement.get_engagements.return_value = engagement
    mock_engagement.post_engagement.return_value = engagement.results[0]
    return mock_engagement


def mock_rest_scan_configuration():
    mock_scan_configuration = MagicMock()
    mock_scan_configuration.post_api_scan_configuration.return_value = ScanConfiguration(
        id=1, service_key_1="service key", tool_configuration=1
    )
    return mock_scan_configuration


# 3. if parameter product_type_empty == True then product_type.resultr == []
@pytest.mark.parametrize(
    """mock_rest_import_scan,
    mock_rest_product_type,
    mock_rest_product,
    mock_rest_scan_configuration,
    import_scan_request_instance,
    mock_rest_engagement""",
    [
        (
            mock_rest_import_scan(file_path="import_scan.json"),
            mock_rest_product_type(),
            mock_rest_product(),
            mock_rest_scan_configuration(),
            import_scan_request_instance(par_scan_type="Xray Scan", file_name="jfrog-xray_on_demand_binary_scan.json"),
            mock_rest_engagement(),
        ),
        (
            mock_rest_import_scan(file_path="import_scan.json", scan_type="Twistlock Scan"),
            mock_rest_product_type(),
            mock_rest_product(),
            mock_rest_scan_configuration(),
            import_scan_request_instance(par_scan_type="Twistlock Scan", file_name="twistlock.csv"),
            mock_rest_engagement(),
        ),
        (
            mock_rest_import_scan(file_path="sonar_qube.json"),
            mock_rest_product_type(),
            mock_rest_product(),
            mock_rest_scan_configuration(),
            import_scan_request_instance(par_scan_type="SonarQube API Import"),
            mock_rest_engagement(),
        ),
        (
            mock_rest_import_scan(file_path="sonar_qube.json"),
            mock_rest_product_type(product_type_empty=True),
            mock_rest_product(),
            mock_rest_scan_configuration(),
            import_scan_request_instance(par_scan_type="SonarQube API Import"),
            mock_rest_engagement(),
        ),
        (
            mock_rest_import_scan(file_path="sonar_qube.json"),
            mock_rest_product_type(),
            mock_rest_product(result_list_empty=True),
            mock_rest_scan_configuration(),
            import_scan_request_instance(par_scan_type="SonarQube API Import"),
            mock_rest_engagement(),
        ),
    ],
)
def test_execute_sucessfull(
    mock_rest_import_scan,
    mock_rest_product_type,
    mock_rest_product,
    mock_rest_scan_configuration,
    import_scan_request_instance,
    mock_rest_engagement,
):
    request = import_scan_request_instance
    uc = ImportScanUserCase(
        rest_import_scan=mock_rest_import_scan,
        rest_product_type=mock_rest_product_type,
        rest_product=mock_rest_product,
        rest_scan_configuration=mock_rest_scan_configuration,
        rest_engagement=mock_rest_engagement,
    )
    assert isinstance(uc, ImportScanUserCase)
    assert isinstance(request, ImportScanRequest)
    response = uc.execute(request)
    assert response.scan_type == import_scan_request_instance.scan_type
    assert response.to_dict()["scan_type"] == import_scan_request_instance.scan_type


@pytest.mark.parametrize(
    """mock_rest_import_scan,
    mock_rest_product_type,
    mock_rest_product,
    mock_rest_scan_configuration,
    import_scan_request_instance,
    mock_rest_engagement""",
    [
        (
            mock_rest_import_scan("import_scan.json"),
            mock_rest_product_type(),
            mock_rest_product(),
            mock_rest_scan_configuration(),
            import_scan_request_instance(par_scan_type="Xray Scan", file_name=""),
            mock_rest_engagement(),
        ),
        (
            mock_rest_import_scan("sonar_qube.json"),
            mock_rest_product_type(),
            mock_rest_product(),
            mock_rest_scan_configuration(),
            import_scan_request_instance(par_scan_type="Xray Scan", file_name=None),
            mock_rest_engagement(),
        ),
        (
            mock_rest_import_scan("sonar_qube.json"),
            mock_rest_product_type(),
            mock_rest_product(),
            mock_rest_scan_configuration(),
            import_scan_request_instance(par_scan_type="Xray Scan", file_name="incorrect url"),
            mock_rest_engagement(),
        ),
    ],
)
def test_execute_error(
    mock_rest_import_scan,
    mock_rest_product_type,
    mock_rest_product,
    mock_rest_scan_configuration,
    import_scan_request_instance,
    mock_rest_engagement,
):
    request = import_scan_request_instance
    uc = ImportScanUserCase(
        rest_import_scan=mock_rest_import_scan,
        rest_product_type=mock_rest_product_type,
        rest_product=mock_rest_product,
        rest_scan_configuration=mock_rest_scan_configuration,
        rest_engagement=mock_rest_engagement,
    )
    assert isinstance(uc, ImportScanUserCase)
    assert isinstance(request, ImportScanRequest)
    with pytest.raises(ApiError):
        uc.execute(request)
