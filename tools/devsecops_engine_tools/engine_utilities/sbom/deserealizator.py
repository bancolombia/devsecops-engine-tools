import json

from devsecops_engine_tools.engine_core.src.domain.model.component import Component


def get_list_component(result_sbom, format) -> "list[Component]":
    list_components = []

    with open(result_sbom, "rb") as file:
        sbom_object = file.read()
        json_data = json.loads(sbom_object)

        if "cyclonedx" in format:
            for component in json_data.get("components", []):
                if component.get("version") != "UNKNOWN":
                    list_components.append(
                        Component(component.get("name"), component.get("version"))
                    )
        return list_components
