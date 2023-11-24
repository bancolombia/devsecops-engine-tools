from common_devsecops_lib.devsecops_engine_utilities.utils.name_conversion import snake_case_to_camel_case


def test_camel_case_to_snake_case():
    result = snake_case_to_camel_case("name_of_test")
    assert result == "nameOfTest"


def test_snake_case_to_camel_case():
    result = snake_case_to_camel_case("hello_world")
    assert result == "helloWorld"
    result = snake_case_to_camel_case("test_case_example")
    assert result == "testCaseExample"
