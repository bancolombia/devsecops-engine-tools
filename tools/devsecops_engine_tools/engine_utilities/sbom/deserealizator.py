import json

from devsecops_engine_tools.engine_core.src.domain.model.component import Component


def get_list_component(result_sbom, format=None) -> "list[Component]":
    list_components = []

    with open(result_sbom, "rb") as file:
        sbom_object = file.read()
        json_data = json.loads(sbom_object)

        is_cyclonedx = (
            "cyclonedx" in format.lower()
            if format is not None
            else json_data.get("bomFormat", "").lower() == "cyclonedx"
        )
        if is_cyclonedx:
            for component in json_data.get("components", []):
                if component.get("version") != "UNKNOWN":
                    component_name = (
                        f"{component.get('group','')}_{component.get('name')}"
                        if component.get("group")
                        else component.get("name")
                    )
                    list_components.append(
                        Component(component_name, component.get("version"))
                    )
        return list_components
