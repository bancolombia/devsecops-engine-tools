import re


def camel_case_to_snake_case(value):
    return re.sub(r"(?<=[a-z])(?=[A-Z])", "_", value).lower()


def snake_case_to_camel_case(value):
    parts = value.split("_")
    parts[0] = parts[0].lower()
    parts[1:] = [part.capitalize() for part in parts[1:]]
    return "".join(parts)
