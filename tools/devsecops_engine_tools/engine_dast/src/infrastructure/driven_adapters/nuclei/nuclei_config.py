from typing import List
import os
from uu import Error
from ruamel.yaml import YAML
from json import dumps as json_dumps


class NucleiConfig:
    def __init__(self, target_config):
        self.url: str = target_config.endpoint
        self.target_type: str = target_config.target_type
        self.custom_templates_dir: str = ""
        self.output_file: str = "result_dast_scan.json"
        self.yaml = YAML()
        if self.target_type.lower() == "api":
            self.data: List = target_config.operations
        elif self.target_type.lower() == "wa":
            self.data: dict = target_config.data
        else:
            raise Error("No se ha podido establecer si el objetivo a escanear es una api o un aplicativo web.")

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
                template_data["http"][0]["method"] = new_template_data["operation"]["method"]
                template_data["http"][0]["path"] = [
                    "{{BaseURL}}" + new_template_data["operation"]["path"]
                ]
                template_data["http"][0]["headers"] = new_template_data["operation"]["headers"]
                if "payload" in new_template_data["operation"]:
                    body = json_dumps(new_template_data["operation"]["payload"])
                    template_data["http"][0]["body"] = body
            elif "ssl" in template_data:
                pass

        new_template_path = os.path.join(dest_folder, new_template_name)

        with open(new_template_path, "w") as nf:
            self.yaml.dump(template_data, nf)

    def process_templates_folder(self, base_folder: str) -> None:
        if not os.path.exists(self.custom_templates_dir):
            os.makedirs(self.custom_templates_dir)

        if self.target_type.lower() == "api":
            t_counter = 0
            for operation in self.data:
                operation.authenticate() #Api Authentication
                for template_name in os.listdir(base_folder):
                    if template_name.endswith(".yaml"):
                        self.process_template_file(
                            base_folder=base_folder,
                            dest_folder=self.custom_templates_dir,
                            template_name=template_name,
                            new_template_data=operation.data,
                            template_counter=t_counter,
                        )
                    t_counter += 1

    def customize_templates(self, directory: str) -> None:
        if self.target_type.lower() == "api":
            self.custom_templates_dir = "customized-nuclei-templates/"
            self.process_templates_folder(
                base_folder=directory
            )
