import pytest
import json
from devsecops_engine_tools.engine_utilities.settings import DEVSECOPS_ENGINE_UTILITIES_PATH
from unittest.mock import MagicMock
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product_type_list import ProductTypeList
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.scan_configuration import ScanConfiguration, ScanConfigurationList
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.product_list import ProductList, Prefetch
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
    file = f"{DEVSECOPS_ENGINE_UTILITIES_PATH}/defect_dojo/test/files/request_file/{file_name}"
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
    rest_product = ProductRestConsumer(SessionManager())
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
    with open(f"{DEVSECOPS_ENGINE_UTILITIES_PATH}/defect_dojo/test/files/{file_path}", "r") as fp:
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


@pytest.mark.parametrize(
    """mock_rest_import_scan,
    mock_rest_product_type,
    mock_rest_product,
    mock_rest_scan_configuration,
    import_scan_request_instance,
    mock_rest_engagement""",
    [
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
def test_execute_reimport_scan(
    mock_rest_import_scan,
    mock_rest_product_type,
    mock_rest_product,
    mock_rest_scan_configuration,
    import_scan_request_instance,
    mock_rest_engagement,
):
    request = import_scan_request_instance
    request.reimport_scan = True
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


def test_request_has_hold_found_product_engagement_field():
    """Verify ImportScanRequest has hold_found_product_engagement field"""
    request = ImportScanRequest(
        engagement_name="test",
        token_defect_dojo="token",
        host_defect_dojo="http://localhost:8000",
        hold_found_product_engagement=True,
    )
    assert hasattr(request, "hold_found_product_engagement")
    assert request.hold_found_product_engagement is True

def test_request_default_hold_found_product_engagement_is_false():
    """Verify hold_found_product_engagement defaults to False"""
    request = ImportScanRequest(
        engagement_name="test",
        token_defect_dojo="token",
        host_defect_dojo="http://localhost:8000",
    )
    assert request.hold_found_product_engagement is False

def test_request_has_engagement_description_field():
    """Verify ImportScanRequest has engagement_description field"""
    request = ImportScanRequest(
        engagement_name="test",
        token_defect_dojo="token",
        host_defect_dojo="http://localhost:8000",
        engagement_description="Test description",
    )
    assert hasattr(request, "engagement_description")
    assert request.engagement_description == "Test description"

def test_request_default_engagement_description_is_empty():
    """Verify engagement_description defaults to empty string"""
    request = ImportScanRequest(
        engagement_name="test",
        token_defect_dojo="token",
        host_defect_dojo="http://localhost:8000",
    )
    assert request.engagement_description == ""

def test_request_from_dict_with_new_fields():
    """Test ImportScanRequest.from_dict() with new fields"""
    data = {
        "product_name": "test product",
        "engagement_name": "test engagement",
        "hold_found_product_engagement": True,
        "engagement_description": "Test description",
        "token_defect_dojo": "token123",
        "host_defect_dojo": "http://localhost:8000",
        "scan_type": "Xray Scan",
    }
    request = ImportScanRequest.from_dict(data)
    assert request.hold_found_product_engagement is True
    assert request.engagement_description == "Test description"

def test_request_to_dict_includes_new_fields():
    """Test ImportScanRequest.to_dict() includes new fields"""
    request = ImportScanRequest(
        product_name="test product",
        engagement_name="test engagement",
        token_defect_dojo="token123",
        host_defect_dojo="http://localhost:8000",
        hold_found_product_engagement=True,
        engagement_description="My description",
    )
    request_dict = request.to_dict()
    assert "hold_found_product_engagement" in request_dict
    assert "engagement_description" in request_dict
    assert request_dict["hold_found_product_engagement"] is True
    assert request_dict["engagement_description"] == "My description"


def test_execute_hold_found_product_engagement_updates_product_context():
    request = import_scan_request_instance(
        par_scan_type="Xray Scan",
        product_name="local-product",
        file_name="jfrog-xray_on_demand_binary_scan.json",
    )
    request.hold_found_product_engagement = True
    request.engagement_name = "shared-engagement"

    local_product = Product(id=1, name="local-product", prod_type=1)
    remote_product = Product(id=999, name="shared-product", prod_type=5)
    remote_prefetch = Prefetch(
        prod_type={
            "5": ProductType(
                id=5,
                name="shared-type",
                description="test",
                critical_product="false",
                key_product="false",
                updated="2023-06-08T19:47:54.838512Z",
                created="2023-06-08T19:47:54.838527Z",
            )
        }
    )

    mock_product = MagicMock()
    mock_product.get_products.side_effect = [
        ProductList(count=1, results=[local_product]),
        ProductList(count=1, results=[remote_product], prefetch=remote_prefetch),
    ]

    mock_engagement = MagicMock()
    mock_engagement.get_engagements.return_value = EngagementList(
        count=1,
        results=[Engagement(id=30, name="shared-engagement", product=999)],
    )
    mock_engagement.post_engagement.return_value = Engagement(id=30, name="shared-engagement", product=999)

    uc = ImportScanUserCase(
        rest_import_scan=mock_rest_import_scan(file_path="import_scan.json"),
        rest_product_type=mock_rest_product_type(),
        rest_product=mock_product,
        rest_scan_configuration=mock_rest_scan_configuration(),
        rest_engagement=mock_engagement,
    )

    uc.execute(request)

    assert request.product_name == "shared-product"
    assert request.product_type_name == "shared-type"
    assert mock_product.get_products.call_args_list[1].args[0] == {
        "id": 999,
        "prefetch": "prod_type",
    }


def test_execute_updates_existing_engagement_when_description_present():
    request = import_scan_request_instance(
        par_scan_type="Xray Scan",
        product_name="product name test",
        file_name="jfrog-xray_on_demand_binary_scan.json",
    )
    request.engagement_name = "name engagement test"
    request.engagement_description = "updated by test"

    mock_engagement = mock_rest_engagement()
    mock_engagement.get_engagements.return_value = EngagementList(
        count=1,
        results=[Engagement(id=3, name="name engagement test", product=1)],
    )
    mock_engagement.patch_engagement.return_value = Engagement(
        id=3,
        name="name engagement test",
        product=1,
    )

    uc = ImportScanUserCase(
        rest_import_scan=mock_rest_import_scan(file_path="import_scan.json"),
        rest_product_type=mock_rest_product_type(),
        rest_product=mock_rest_product(),
        rest_scan_configuration=mock_rest_scan_configuration(),
        rest_engagement=mock_engagement,
    )

    uc.execute(request)

    mock_engagement.patch_engagement.assert_called_once()
    assert mock_engagement.patch_engagement.call_args.args[1] == 3


def test_execute_creates_engagement_when_name_matches_but_product_differs_without_hold():
    request = import_scan_request_instance(
        par_scan_type="Xray Scan",
        product_name="product name test",
        file_name="jfrog-xray_on_demand_binary_scan.json",
    )
    request.hold_found_product_engagement = False
    request.engagement_name = "shared-engagement"

    mock_engagement = MagicMock()
    mock_engagement.get_engagements.return_value = EngagementList(
        count=1,
        results=[Engagement(id=77, name="shared-engagement", product=999)],
    )
    mock_engagement.post_engagement.return_value = Engagement(
        id=88,
        name="shared-engagement",
        product=1,
    )

    uc = ImportScanUserCase(
        rest_import_scan=mock_rest_import_scan(file_path="import_scan.json"),
        rest_product_type=mock_rest_product_type(),
        rest_product=mock_rest_product(),
        rest_scan_configuration=mock_rest_scan_configuration(),
        rest_engagement=mock_engagement,
    )

    uc.execute(request)

    mock_engagement.post_engagement.assert_called_once()


def test_import_scan_timeout_returns_partial_response_with_url():
    """Test import_scan handles a '504 Gateway Time-out' error by returning a partial response"""
    request = import_scan_request_instance(
        par_scan_type="Xray Scan",
        file_name="jfrog-xray_on_demand_binary_scan.json",
    )
    mock_import_scan = MagicMock()
    mock_import_scan.import_scan.side_effect = Exception("504 Gateway Time-out")

    uc = ImportScanUserCase(
        rest_import_scan=mock_import_scan,
        rest_product_type=mock_rest_product_type(),
        rest_product=mock_rest_product(),
        rest_scan_configuration=mock_rest_scan_configuration(),
        rest_engagement=mock_rest_engagement(),
    )

    response = uc.import_scan(request, api_scan_bool=False)

    assert response.url == request.host_defect_dojo


def test_execute_raises_when_product_name_and_type_name_empty():
    """Test execute raises ApiError when both product_name and product_type_name are empty"""
    request = import_scan_request_instance(par_scan_type="Xray Scan", product_name="")
    request.product_type_name = ""

    uc = ImportScanUserCase(
        rest_import_scan=mock_rest_import_scan(file_path="import_scan.json"),
        rest_product_type=mock_rest_product_type(),
        rest_product=mock_rest_product(),
        rest_scan_configuration=mock_rest_scan_configuration(),
        rest_engagement=mock_rest_engagement(),
    )

    with pytest.raises(ApiError):
        uc.execute(request)


def test_execute_creates_product_type_when_none_found():
    """Test execute creates a new product_type when none matches and no product was found"""
    request = import_scan_request_instance(
        par_scan_type="Xray Scan",
        file_name="jfrog-xray_on_demand_binary_scan.json",
    )

    mock_product_type = mock_rest_product_type(product_type_empty=True)

    uc = ImportScanUserCase(
        rest_import_scan=mock_rest_import_scan(file_path="import_scan.json"),
        rest_product_type=mock_product_type,
        rest_product=mock_rest_product(result_list_empty=True),
        rest_scan_configuration=mock_rest_scan_configuration(),
        rest_engagement=mock_rest_engagement(),
    )

    uc.execute(request)

    mock_product_type.post_product_type.assert_called_once_with(request.product_type_name)


def test_execute_warns_when_multiple_product_types_found():
    """Test execute logs a warning when more than one product_type matches the search"""
    request = import_scan_request_instance(
        par_scan_type="Xray Scan",
        file_name="jfrog-xray_on_demand_binary_scan.json",
    )

    product_type_1 = ProductType(
        id=1, name="type1", description="test", critical_product="false",
        key_product="false", updated="2023-06-08T19:47:54.838512Z", created="2023-06-08T19:47:54.838527Z",
    )
    product_type_2 = ProductType(
        id=2, name="type2", description="test", critical_product="false",
        key_product="false", updated="2023-06-08T19:47:54.838512Z", created="2023-06-08T19:47:54.838527Z",
    )
    mock_product_type = MagicMock()
    mock_product_type.get_product_types.return_value = ProductTypeList(
        count=2, results=[product_type_1, product_type_2]
    )

    uc = ImportScanUserCase(
        rest_import_scan=mock_rest_import_scan(file_path="import_scan.json"),
        rest_product_type=mock_product_type,
        rest_product=mock_rest_product(result_list_empty=True),
        rest_scan_configuration=mock_rest_scan_configuration(),
        rest_engagement=mock_rest_engagement(),
    )

    response = uc.execute(request)

    assert response.scan_type == request.scan_type
    mock_product_type.post_product_type.assert_not_called()


def test_execute_creates_api_scan_configuration_when_none_found():
    """Test execute creates an API scan configuration when none matches the search"""
    request = import_scan_request_instance(par_scan_type="SonarQube API Import")

    mock_scan_configuration = MagicMock()
    mock_scan_configuration.get_api_scan_configuration.return_value = ScanConfigurationList(count=0, results=[])
    mock_scan_configuration.post_api_scan_configuration.return_value = ScanConfiguration(
        id=1, service_key_1="new service key", tool_configuration=1
    )

    uc = ImportScanUserCase(
        rest_import_scan=mock_rest_import_scan(file_path="sonar_qube.json"),
        rest_product_type=mock_rest_product_type(),
        rest_product=mock_rest_product(),
        rest_scan_configuration=mock_scan_configuration,
        rest_engagement=mock_rest_engagement(),
    )

    response = uc.execute(request)

    mock_scan_configuration.post_api_scan_configuration.assert_called_once()
    assert response.scan_type == request.scan_type
