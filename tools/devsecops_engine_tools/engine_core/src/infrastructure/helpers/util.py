from datetime import datetime


def format_date(date, to_format, from_format):
    return datetime.strptime(date, to_format).strftime(from_format)


def define_env(variable_env, branch):
    if variable_env is not None:
        return variable_env.lower()
    return (
        "pdn"
        if branch in ["trunk", "master"]
        else "qa" if branch=="release" else "dev"
    )
