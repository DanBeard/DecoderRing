from Package import Package
from typing import List


class BaseSerializer:
    """
    Abstract class representing the base decoder ring
    """

    def serialize(self, packages: List[Package]) -> str:
        raise NotImplemented()

    def deserialize(self, text: str) -> List[Package]:
        raise NotImplemented()


