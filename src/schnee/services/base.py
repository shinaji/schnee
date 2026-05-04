from abc import ABC, abstractmethod
from typing import TypeVar

from pydantic import BaseModel, ConfigDict

ReqType = TypeVar("ReqType", bound="_RequestBase")


class _RequestBase(BaseModel):
    model_config = ConfigDict(frozen=True)


class _ServiceCore[T](ABC):
    """Service core class"""

    class Request(_RequestBase): ...

    def __init__(self, req: ReqType) -> None:
        self.req = req

    @abstractmethod
    def process(self) -> T: ...

    @classmethod
    def call(cls, req: ReqType) -> T:
        """Process the request"""
        return cls(req=req).process()


class Service[T](_ServiceCore[T]):
    """Service base class"""
