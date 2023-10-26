from abc import ABC, abstractmethod


# pylint: disable=too-few-public-methods
class MessageBusPlugin(ABC):
    @abstractmethod
    def produce_msg(self, message):
        pass
