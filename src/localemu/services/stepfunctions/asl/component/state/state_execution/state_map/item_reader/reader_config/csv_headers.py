from typing import Final

from localemu.services.stepfunctions.asl.component.component import Component


class CSVHeaders(Component):
    header_names: Final[list[str]]

    def __init__(self, header_names: list[str]):
        self.header_names = header_names
