import os
import yaml

class TargetConfig:

    def __init__(self, data: dict):
        self.url: str = data.get("url")
        self.target_type: str = self.match_target_scan_type(data)
        self.data: dict = data
        self.custom_templates_dir: str = None
        self.output_file: str = "result_dast_scan.json"
        self.match_target_scan_type()

    def match_target_scan_type(self, data):
        if "operations" in data:
            return "API"
        else:
            return "AW"
        
    def process_template_file(
            self, 
            base_folder: str, 
            dest_folder: str,
            template_name: str, 
            new_template_data: dict, 
            template_counter: int) -> None:
        
        new_template_name: str = "nuclei_template_" + str(template_counter) + ".yaml"
        
        template_file_path = os.path.join(base_folder, template_name)
        with open(template_file_path, "r") as template_file: #abrir  archivo
            template_data = yaml.safe_load(template_file)
            if "http" in template_data:
                template_data["http"]["method"] = new_template_data["operation"]["method"]
                template_data["http"]["path"] = "{{BaseURL}}" + new_template_data["operation"]["path"]
                template_data["http"]["headers"] = new_template_data["operation"]["headers"]
                if "payload" in new_template_data["operation"]:
                    pass
            elif "ssl" in template_data:
                pass
            elif "dns" in template_data:
                pass
                

        new_template_path = os.path.join(dest_folder, new_template_name)

        with open(new_template_path, 'w') as nf:
            yaml.safe_dump(template_data, nf)

    def process_templates_folder(
            self, 
            base_folder: str, 
            dest_folder: str
        ) -> None:

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
                        template_counter=template_counter
                        )
                template_counter += 1

    def customize_templates(self, directory: str) -> None:
        new_directory: str = directory
        if self.target_type == "API":
            new_directory: str = "customized-templates"

            self.custom_templates_dir = new_directory
