import re


def camel_case_to_snake_case(value):
    return re.sub(r"(?<=[a-z])(?=[A-Z])", "_", value).lower()


def snake_case_to_camel_case(value):
    parts = value.split("_")
    parts[0] = parts[0].lower()
    parts[1:] = [part.capitalize() for part in parts[1:]]
    return "".join(parts)


def dict_casing_conversion(obj, conversion_function):
    if isinstance(obj, dict):
        return {
            conversion_function(key): dict_casing_conversion(value, conversion_function) for key, value in obj.items()
        }
    elif isinstance(obj, list):
        return [dict_casing_conversion(
            element, conversion_function) for element in obj]
    return obj


def navitaire_naming_to_internal(value):
    return dict_casing_conversion(value, camel_case_to_snake_case)


def internal_naming_to_navitaire(value):
    return dict_casing_conversion(value, snake_case_to_camel_case)
