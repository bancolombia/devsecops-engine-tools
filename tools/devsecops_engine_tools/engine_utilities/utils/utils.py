import zipfile
import base64

class Utils:

    def unzip_file(self, zip_file_path, extract_path):
        with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
            zip_ref.extractall(extract_path)

    def encode_token_to_base64(self, token):
        token_bytes = f"{token}:".encode("utf-8")
        base64_token = base64.b64encode(token_bytes).decode("utf-8")
        return base64_token