from abc import ABC, abstractmethod


# pylint: disable=too-few-public-methods
class InformerPlugin(ABC):
    @abstractmethod
    def handle_event(self, message):
        pass
