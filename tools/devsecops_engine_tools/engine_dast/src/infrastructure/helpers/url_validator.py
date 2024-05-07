import validators


def url_validator(url):
    """
    Validates if a given URL is valid or not.

    Args:
        url (str): The URL to be validated.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    if validators.url(url):
        return True
    else:
        return False
