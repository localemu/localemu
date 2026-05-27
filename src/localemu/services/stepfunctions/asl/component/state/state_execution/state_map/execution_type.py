from enum import Enum

from localemu.services.stepfunctions.asl.antlr.runtime.ASLLexer import ASLLexer


class ExecutionType(Enum):
    Standard = ASLLexer.STANDARD
