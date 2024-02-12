import os
from ruamel.yaml import YAML
from devsecops_engine_tools.engine_dast.src.domain.model.target_config import (
    TargetConfig,
)


class NucleiConfig:
    def __init__(self, target_config: TargetConfig):
        self.url: str = target_config.url
        self.target_type: str = target_config.target_type
        self.data: dict = target_config.data
        self.custom_templates_dir: str = None
        self.output_file: str = "azp/_work/r1/a/" + "result_dast_scan.json"
        self.yaml = YAML()

    def process_template_file(
        self,
        base_folder: str,
        dest_folder: str,
        template_name: str,
        new_template_data: dict,
        template_counter: int,
    ) -> None:
        new_template_name: str = "nuclei_template_" + str(template_counter) + ".yaml"

        template_file_path = os.path.join(base_folder, template_name)
        with open(template_file_path, "r") as template_file:  # abrir  archivo
            template_data = self.yaml.load(template_file)
            if "http" in template_data:
                security_auth = new_template_data.get("operation").get("security_auth")
                template_data["http"][0]["method"] = new_template_data["operation"]
                ["method"]
                template_data["http"][0]["path"] = [
                    "{{BaseURL}}" + new_template_data["operation"]["path"]
                ]
                auth_type = security_auth.get("type")
                if auth_type == "client_secret":
                    template_data["http"][0]["headers"] = new_template_data[
                        "operation"
                    ]["headers"]
                elif auth_type == "jwt":
                    new_template_data["operation"]["headers"][
                        "Authorization"
                    ] = get_token()
                if "payload" in new_template_data["operation"]:
                    pass
            elif "ssl" in template_data:
                pass
            elif "dns" in template_data:
                pass

        new_template_path = os.path.join(dest_folder, new_template_name)

        with open(new_template_path, "w") as nf:
            self.yaml.dump(template_data, nf)

    def process_templates_folder(self, base_folder: str, dest_folder: str) -> None:
        if not os.path.exists(dest_folder):
            os.makedirs(dest_folder)

        template_counter = 0
        for operation in self.data.get("operations"):
            for template_name in os.listdir(base_folder):
                if template_name.endswith(".yaml"):
                    self.process_template_file(
                        base_folder=base_folder,
                        dest_folder=dest_folder,
                        template_name=template_name,
                        new_template_data=operation,
                        template_counter=template_counter,
                    )
                template_counter += 1

    def customize_templates(self, directory: str) -> None:
        if self.target_type == "API":
            new_directory: str = "azp/_work/r1/a/customized-templates/"
            self.custom_templates_dir = new_directory
            self.process_templates_folder(
                base_folder=directory, dest_folder=new_directory
            )
