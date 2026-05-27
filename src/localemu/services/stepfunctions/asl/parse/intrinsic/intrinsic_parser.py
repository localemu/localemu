import abc

from antlr4 import CommonTokenStream, InputStream
from antlr4.ParserRuleContext import ParserRuleContext

from localemu.services.stepfunctions.asl.antlr.runtime.ASLIntrinsicLexer import ASLIntrinsicLexer
from localemu.services.stepfunctions.asl.antlr.runtime.ASLIntrinsicParser import (
    ASLIntrinsicParser,
)
from localemu.services.stepfunctions.asl.component.intrinsic.function.function import Function
from localemu.services.stepfunctions.asl.parse.intrinsic.preprocessor import Preprocessor


class IntrinsicParser(abc.ABC):
    @staticmethod
    def parse(src: str) -> tuple[Function, ParserRuleContext]:
        input_stream = InputStream(src)
        lexer = ASLIntrinsicLexer(input_stream)
        stream = CommonTokenStream(lexer)
        parser = ASLIntrinsicParser(stream)
        tree = parser.func_decl()
        preprocessor = Preprocessor()
        function: Function = preprocessor.visit(tree)
        return function, tree
