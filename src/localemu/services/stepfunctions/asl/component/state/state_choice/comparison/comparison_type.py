from __future__ import annotations

from abc import ABC

from localemu.services.stepfunctions.asl.component.eval_component import EvalComponent


class Comparison(EvalComponent, ABC): ...
