import abc

from localemu.services.stepfunctions.asl.component.eval_component import EvalComponent


class JSONataTemplateValue(EvalComponent, abc.ABC): ...
