from localemu.services.stepfunctions.asl.component.component import Component
from localemu.services.stepfunctions.asl.component.state.state import CommonStateField


class States(Component):
    def __init__(self):
        self.states: dict[str, CommonStateField] = {}
