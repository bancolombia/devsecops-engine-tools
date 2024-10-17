from abc import ABCMeta, abstractmethod


class MetricsManagerGateway(metaclass=ABCMeta):
    @abstractmethod
    def send_metrics(self, config_tool, tool, file_path):
        "send_metrics"
