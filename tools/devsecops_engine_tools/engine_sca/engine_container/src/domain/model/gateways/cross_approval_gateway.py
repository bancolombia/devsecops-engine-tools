from abc import ABCMeta, abstractmethod


class CrossApprovalGateway(metaclass=ABCMeta):
    @abstractmethod
    def get_approved_exclusions(self, url: str, token: str):
        """Get currently approved cross-approval exclusions."""