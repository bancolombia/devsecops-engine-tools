from abc import ABCMeta, abstractmethod


class AddEpssGateway(metaclass=ABCMeta):
    @abstractmethod
    def add_epss_data(self, findings) -> list:
        "run add epss tool"
