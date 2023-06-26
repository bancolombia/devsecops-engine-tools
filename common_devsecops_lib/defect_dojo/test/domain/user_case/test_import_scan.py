import pytest
import json
from unittest.mock import MagicMock
from defect_dojo.domain.models.product_type_list\
    import ProductTypeList
from defect_dojo.domain.models.scan_configuration\
    import ScanConfiguration
from defect_dojo.domain.models.product_list import ProductList
from defect_dojo.domain.models.product import Product
from defect_dojo.domain.models.product_type import ProductType
from defect_dojo.infraestructure.driver_adapters.import_scan\
    import ImportScanRestConsumer
from defect_dojo.infraestructure.driver_adapters.product_type\
    import ProductTypeRestConsumer
from defect_dojo.infraestructure.driver_adapters.product\
    import ProductRestConsumer
from defect_dojo.infraestructure.driver_adapters\
    .scan_configurations import ScanConfigrationRestConsumer
from defect_dojo.domain.request_objects.import_scan\
    import ImportScanRequest
from defect_dojo.domain.user_case.import_scan\
    import ImportScanUserCase
from helper.validation_error import ValidationError


def import_scan_request_instance(par_scan_type,
                                 product_name="test product name") -> ImportScanRequest:
    request = ImportScanRequest(
        product_name=product_name,
        token="123456789",
        host="https://test/test.com",
        token_vultracker="123456789101212",
        host_vultracker="http://localhost:8000",
        scan_type=par_scan_type,
        engagement_name="test engagement name",
        file="defect_dojo/test/files/xray_scan.json",
        tags="evc",
    )
    return request


def test_user_case_creation():
    request = import_scan_request_instance("Xray scan")
    assert isinstance(request, ImportScanRequest)
    rest_import_scan = ImportScanRestConsumer(request)
    rest_product_type = ProductTypeRestConsumer(request)
    rest_product = ProductRestConsumer(request)
    rest_scan_configuration = ScanConfigrationRestConsumer(request)
    uc = ImportScanUserCase(
        rest_import_scan=rest_import_scan,
        rest_product_type=rest_product_type,
        rest_product=rest_product,
        rest_scan_configuration=rest_scan_configuration,
    )
    assert isinstance(uc, object)
    assert hasattr(uc, "__init__")
    assert hasattr(uc, "execute")


def mock_rest_import_scan(file_path):
    mock_import_scan = MagicMock()
    with open(f"defect_dojo/test/files/{file_path}", "r") as fp:
        data = json.load(fp)
        import_scan_object = ImportScanRequest.from_dict(data)
        assert import_scan_object.scan_type == data["scan_type"]
        assert import_scan_object.product_type_name == data["product_type_name"]
        assert import_scan_object.engagement_name == data["engagement_name"]
        mock_import_scan.import_scan_api.return_value = import_scan_object
        mock_import_scan.import_scan.return_value = import_scan_object
    return mock_import_scan


def mock_rest_product_type():
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
    mock_rest_product_type.get_product_types.return_value = ProductTypeList(
        count=1, results=products
    )
    mock_rest_product_type.post_product_type.return_value = products[0]
    return mock_rest_product_type


def mock_rest_product():
    mock_product = MagicMock()
    products = ProductList(count=1, results=[Product(id=1, name="product name test")])
    mock_product.get_products.return_value = products
    product = Product(id=1, name="product name test")
    mock_product.post_product.return_value = product
    return mock_product


def mock_rest_scan_configuration():
    mock_scan_configuration = MagicMock()
    mock_scan_configuration.post_api_scan_configuration.return_value = (
        ScanConfiguration(id=1,
                          service_key_1="service key",
                          tool_configuration=1)
    )
    return mock_scan_configuration


@pytest.mark.parametrize(
    """mock_rest_import_scan,
    mock_rest_product_type,
    mock_rest_product,
    mock_rest_scan_configuration,
    import_scan_request_instance""",
    [
        (
            mock_rest_import_scan("import_scan_xray.json"),
            mock_rest_product_type(),
            mock_rest_product(),
            mock_rest_scan_configuration(),
            import_scan_request_instance("Xray Scan"),
        ),
        (
            mock_rest_import_scan("sonar_qube.json"),
            mock_rest_product_type(),
            mock_rest_product(),
            mock_rest_scan_configuration(),
            import_scan_request_instance("SonarQube API Import"),
        ),
    ],
)
def test_execute_sucessfull(
    mock_rest_import_scan,
    mock_rest_product_type,
    mock_rest_product,
    mock_rest_scan_configuration,
    import_scan_request_instance,
):
    request = import_scan_request_instance
    uc = ImportScanUserCase(
        rest_import_scan=mock_rest_import_scan,
        rest_product_type=mock_rest_product_type,
        rest_product=mock_rest_product,
        rest_scan_configuration=mock_rest_scan_configuration,
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
    import_scan_request_instance""",
    [
        (
            mock_rest_import_scan("import_scan_xray.json"), 
            mock_rest_product_type(),
            mock_rest_product(),
            mock_rest_scan_configuration(),
            import_scan_request_instance("Xray Scan", ""),
        ),
        (
            mock_rest_import_scan("sonar_qube.json"),
            mock_rest_product_type(),
            mock_rest_product(),
            mock_rest_scan_configuration(),
            import_scan_request_instance("Xray Scan", None),
        ),
    ],
)
def test_execute_error(
    mock_rest_import_scan,
    mock_rest_product_type,
    mock_rest_product,
    mock_rest_scan_configuration,
    import_scan_request_instance,
):
    request = import_scan_request_instance
    uc = ImportScanUserCase(
        rest_import_scan=mock_rest_import_scan,
        rest_product_type=mock_rest_product_type,
        rest_product=mock_rest_product,
        rest_scan_configuration=mock_rest_scan_configuration,
    )
    assert isinstance(uc, ImportScanUserCase)
    assert isinstance(request, ImportScanRequest)
    print("pasoooo")
    with pytest.raises(ValidationError) as e:
        response = uc.execute(request)
        assert str(e.value) == "Name product not found"
