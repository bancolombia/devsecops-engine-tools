from dataclasses import dataclass
from abc import ABCMeta, abstractmethod


@dataclass
class Token(metaclass=ABCMeta):
    token: str

    @abstractmethod
    def get_token(self):
        "return_token"
