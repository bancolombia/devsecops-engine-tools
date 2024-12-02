from abc import ABCMeta, abstractmethod
from devsecops_engine_tools.engine_core.src.domain.model.component import (
    Component,
)

class SbomManagerGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_components(
        self, artifact, config, service_name
    ) -> "list[Component]":
        "get_components"
