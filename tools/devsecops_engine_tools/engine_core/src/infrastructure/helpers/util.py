from datetime import datetime


def format_date(date, to_format, from_format):
    return datetime.strptime(date, to_format).strftime(from_format)


def format_optional_date(date, input_format="%d%m%Y", output_format="%d/%m/%Y"):
    """
    Formats a date that may not be defined. Exclusions can legitimately come without
    dates (the Exclusions model defaults them to an empty string), so rendering them
    must not fail.
    """
    if date and date != "undefined":
        return format_date(date, input_format, output_format)
    return "NA"


def format_expired_date(expired_date, input_format="%d%m%Y", output_format="%d/%m/%Y"):
    return format_optional_date(expired_date, input_format, output_format)


def define_env(variable_env, branch):
    if variable_env is not None:
        return variable_env.lower()
    if branch in ["trunk", "master"]:
        return "pdn"
    elif branch == "release":
        return "qa"
    else:
        return "dev"
