import json


def load_json_file(file_path: str):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        raise FileNotFoundError(f"Error: The file '{file_path}' was not found.")
    except json.JSONDecodeError:
        raise json.JSONDecodeError(f"Error: The file '{file_path}' does not contain valid JSON.")
    except IOError as e:
        raise IOError(f"I/O Error: {e}")