from typing import List
import os
from ruamel.yaml import YAML
from json import dumps as json_dumps

class NucleiConfig:
    def __init__(self, target_config):
        self.url: str = target_config.endpoint
        self.target_type: str = target_config.target_type.lower()
        self.custom_templates_dir: str = ""
        self.output_file: str = "result_dast_scan.json"
        self.concurrency: int = target_config.concurrency
        self.rate_limit: int = target_config.rate_limit
        self.response_size: int = target_config.response_size
        self.bulk_size: int = target_config.bulk_size
        self.timeout: int = target_config.timeout
        self.yaml = YAML()
        if self.target_type == "api":
            self.data: List = target_config.operations
        elif self.target_type == "wa":
            self.data: dict = target_config.data
        else:
            raise ValueError("ERROR: The objective is not an api or web application type")

    def process_template_file(
        self,
        dest_folder: str,
        template_name: str,
        new_template_data: dict,
        template_counter: int,
    ) -> None:
        new_template_name: str = "nuclei_template_" + str(template_counter) + ".yaml"
        with open(template_name, "r") as template_file:  # abrir  archivo
            template_data = self.yaml.load(template_file)
            if "http" in template_data:
                template_data["http"][0]["method"] = new_template_data["operation"]["method"]
                template_data["http"][0]["path"] = [
                    "{{BaseURL}}" + new_template_data["operation"]["path"]
                ]
                if "headers" in new_template_data["operation"]:
                    if "headers" not in template_data["http"][0]:
                        template_data["http"][0]["headers"] = new_template_data["operation"]["headers"]
                    else:
                        for header, value in new_template_data["operation"]["headers"].items():
                            if header not in template_data["http"][0]["headers"]:
                                template_data["http"][0]["headers"][header] = value
                if "payload" in new_template_data["operation"]:
                    body = json_dumps(new_template_data["operation"]["payload"])
                    template_data["http"][0]["body"] = body

        new_template_path = os.path.join(dest_folder, new_template_name)

        with open(new_template_path, "w") as nf:
            self.yaml.dump(template_data, nf)

    def process_templates_folder(self, base_folder: str) -> None:
        if not os.path.exists(self.custom_templates_dir):
            os.makedirs(self.custom_templates_dir)

        t_counter = 0
        for operation in self.data:
            operation.authenticate() #Api Authentication
            for root, _, files in os.walk(f"{base_folder}{os.sep}rules{os.sep}nuclei"):
                for file in files:
                    if file.endswith(".yaml"):
                        self.process_template_file(
                            dest_folder=self.custom_templates_dir,
                            template_name=os.path.join(root, file),
                            new_template_data=operation.data,
                            template_counter=t_counter,
                        )
                        t_counter += 1

    def customize_templates(self, directory: str) -> None:
        if self.target_type == "api":
            self.custom_templates_dir = f"{directory}{os.sep}customized-nuclei-templates"
            self.process_templates_folder(
                base_folder=directory
            )
