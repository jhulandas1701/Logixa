from abc import ABC, abstractmethod
from typing import Any
class Parser(ABC):
    name='base'; version='1.0'
    @abstractmethod
    def parse(self, raw: str) -> dict[str, Any]: ...
