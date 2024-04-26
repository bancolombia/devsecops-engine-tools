import re


def validate_input_with_regex(value, input_name):
    pattern = r"^[a-zA-Z0-9_]+$"
    if not re.match(pattern, value):
        raise ValueError(f"Error: Invalid input for {input_name}. Only letters and numbers are allowed.")
    return value
