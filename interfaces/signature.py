from abc import ABC, abstractmethod
from typing import Any

class AbstractSignature(ABC):
    @abstractmethod
    def keygen(self, seed: bytes = None) -> tuple[Any, Any]: pass

    @abstractmethod
    def sign(self, sk, message: bytes, t: int): pass

    @abstractmethod
    def verify(self, pk, message, signature, t: int): pass

    @abstractmethod
    def get_total_time_periods(self) -> int: pass

    @abstractmethod
    def update(self, t: int): pass

    @abstractmethod
    def p_keygen(self, seed: bytes = None): pass

    @abstractmethod
    def s_keygen(self, seed: bytes = None): pass

    @abstractmethod
    def cleanup(self): pass