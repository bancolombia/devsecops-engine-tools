import os
import re

def search_folders(search_pattern, ignore_pattern):
    current_directory = os.getcwd()
    patron = (
        "(?i)(?!.*(?:"
        + "|".join(ignore_pattern)
        + ")).*?("
        + "|".join(search_pattern)
        + ").*$"
    )
    folders = [
        folder
        for folder in os.listdir(current_directory)
        if os.path.isdir(os.path.join(current_directory, folder))
    ]
    matching_folders = [
        os.path.normpath(os.path.join(current_directory, folder))
        for folder in folders
        if re.match(patron, folder)
    ]
    return matching_folders