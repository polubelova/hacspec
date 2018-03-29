#!/usr/bin/python3

from typed_ast.ast3 import *
from sys import argv, exit, exc_info
import builtins
import os
from collections import Iterable

DEBUG_PRINT = True


def print(*args, **kwargs):
    if DEBUG_PRINT:
        builtins.print(*args, **kwargs)


class AstItem():
    def __init__(self, t, args=None):
        self.t = t
        self.args = []
        if args is not None:
            if isinstance(args, str):
                self.args.append(args)
            else:
                for a in args:
                    self.args.append(a)

    def get_function_signature(self):
        assert(self.t.__name__ == "FunctionDef")
        assert(isinstance(self.args[0], FunctionSignature))
        return self.args[0]

class AstReader():
    def __init__(self, ast):
        self.ast = ast
        self.objects = []

    def read_function_signature(self, f):
        fun_name = f.name
        if f.args.args is not None:
            arg_types = [x.annotation.id for x in f.args.args]
        if f.returns is not None:
            if isinstance(f.returns, Name):
                rt = f.returns.id
            elif isinstance(f.returns, Subscript):
                rt = f.returns.slice.value
                if not isinstance(rt, Tuple):
                    print("Return types have to be simple types or tuples, not " + str(type(rt)) + ".")
                    exit(1)
                rt = [x.id for x in rt.elts]
        else:
            print("Functions must have a return type (use None for void functions).")
            exit(1)
        if len(f.decorator_list) != 0:
            print("Function argument decorators are not supported in hacspec.")
            exit(1)
        if len(f.args.defaults) != 0:
            print("Default arguments are not supported in hacspec.")
            exit(1)
        if f.type_comment is not None:
            print("Type comments on functions are not allowed in hacspec.")
            exit(1)
        if len(f.args.kwonlyargs) != 0:
            print("keyword only args are not allowed in hacspec.")
            exit(1)
        if f.args.vararg is not None:
            print("varargs are not allowed in hacspec")
            exit(1)
        if len(f.args.kw_defaults) != 0:
            print("keyword defaults are not allowed in hacspec")
            exit(1)
        if f.args.kwarg is not None:
            print("keyword args are not allowed in hacspec")
            exit(1)
        # TODO: be stricter and check everything.
        return FunctionSignature.create(fun_name, arg_types, rt)

    def read(self, node):
        # FIXME: this shouldn't be allowed
        if node is None:
            print(" >>>>>>>>> none node in spec (something is probably wrong)")
            return

        if isinstance(node, Module):
            return AstItem(Module, [self.read(node.body)])

        if isinstance(node, ImportFrom):
            return AstItem(ImportFrom, [node.module])

        if isinstance(node, Tuple):
            tuples = []
            for e in node.elts:
                tuples.append(self.read(e))
            return AstItem(Tuple, tuples)

        # Normal assignments with types in comments
        if isinstance(node, Assign):
            args = [[self.read(t) for t in node.targets]]
            args.append(self.read(node.value))
            if node.type_comment:
                print("Type comments are not supported by hacspec")
                exit(1)
            return AstItem(Assign, args)

        if isinstance(node, AugAssign):
            target = self.read(node.target)
            op = self.read(node.op)
            value = self.read(node.value)
            return AstItem(AugAssign, [target, op, value])

        if isinstance(node, AnnAssign):
            args = [self.read(node.target)]
            if node.value:
                args.append(self.read(node.value))
            args.append(self.read(node.annotation))
            return AstItem(AnnAssign, args)

        if isinstance(node, List):
            l = []
            for elt in node.elts:
                l.append(self.read(elt))
            return AstItem(List, l)

        if isinstance(node, Attribute):
            return AstItem(Attribute, [AstItem(str, node.attr), self.read(node.value)])

        if isinstance(node, BinOp):
            left = self.read(node.left)
            op = self.read(node.op)
            right = self.read(node.right)
            return AstItem(BinOp, [left, op, right])

        # Primitive types
        if isinstance(node, Num):
            return AstItem(Num)

        if isinstance(node, Name):
            # ctx = self.read(node.ctx, prev=previous)
            # print(indent+node.id+" "+str(ctx))
            return AstItem(Name, [AstItem(str, node.id)])

        if isinstance(node, Load):
            return AstItem(Load)
        if isinstance(node, Store):
            return AstItem(Store)
        if isinstance(node, AugStore):
            return AstItem(AugStore)
        if isinstance(node, AugLoad):
            return AstItem(AugLoad)

        # Loops
        if isinstance(node, For):
            args = [self.read(node.target)]
            if node.body:
                args.append(self.read(node.body))
            if node.orelse:
                args.append(self.read(node.orelse))
            if node.iter:
                args.append(self.read(node.iter))
            return AstItem(For, args)

        # Operators
        if isinstance(node, Pow):
            return AstItem(Pow)
        if isinstance(node, Sub):
            return AstItem(Sub)
        if isinstance(node, Mult):
            return AstItem(Mult)
        if isinstance(node, Add):
            return AstItem(Add)
        if isinstance(node, Mod):
            return AstItem(Mod)
        if isinstance(node, FloorDiv):
            return AstItem(FloorDiv)
        if isinstance(node, Div):
            return AstItem(FloorDiv)
        if isinstance(node, BitXor):
            return AstItem(BitXor)
        if isinstance(node, RShift):
            return AstItem(RShift)
        if isinstance(node, BitAnd):
            return AstItem(BitAnd)
        if isinstance(node, BitOr):
            return AstItem(BitOr)
        if isinstance(node, UnaryOp):
            return AstItem(UnaryOp)
        if isinstance(node, Compare):
            return AstItem(Compare)
        if isinstance(node, LShift):
            return AstItem(LShift)

        if isinstance(node, BoolOp):
            values = [node.op]
            for ex in node.values:
                values.append(self.read(ex, prev=previous))
            return AstItem(BoolOp, values)

        if isinstance(node, Subscript):
            return AstItem(Subscript, [self.read(node.value), AstItem(slice, [node.slice])])

        # Functions
        if isinstance(node, FunctionDef):
            sig = self.read_function_signature(node)
            body = self.read(node.body)
            return AstItem(FunctionDef, [sig, body])

        if isinstance(node, Return):
            return AstItem(Return, [self.read(node.value)])

        if isinstance(node, Call):
            args = [self.read(node.func)]
            if node.args:
                args.append(self.read(node.args))
            # TODO: read keywords?
            return AstItem(Call, args)

        if isinstance(node, Expr):
            return AstItem(Expr, [self.read(node.value)])

        if isinstance(node, If):
            test = self.read(node.test)
            body = self.read(node.body)
            orelse = self.read(node.orelse)
            return AstItem(If, [test, orelse, body])

        if isinstance(node, While):
            test = self.read(node.test)
            body = self.read(node.body)
            orelse = self.read(node.orelse)
            return AstItem(While, [test, orelse, body])

        if isinstance(node, Str):
            return AstItem(Str, [node.s])

        if isinstance(node, arguments):
            args = [self.read(a) for a in node.args]
            if len(node.defaults) != 0:
                print("Default arguments are not supported in hacspec.")
                exit(1)
            if len(node.kwonlyargs) != 0:
                print("keyword only args are not allowed in hacspec.")
                exit(1)
            if node.vararg is not None:
                print("varargs are not allowed in hacspec")
                exit(1)
            if len(node.kw_defaults) != 0:
                print("keyword defaults are not allowed in hacspec")
                exit(1)
            if node.kwarg is not None:
                print("keyword args are not allowed in hacspec")
                exit(1)
            return AstItem(arguments, args)

        if isinstance(node, arg):
            return AstItem(arg)

        # TODO: lambdas are only allowed in refine_t statements
        if isinstance(node, Lambda):
            args = self.read(node.args)
            body = self.read(node.body)
            return AstItem(Lambda, [args, body])

        # Explicitly disallowed statements
        if isinstance(node, With):
            print("With is not allowed in hacspec.")
            exit(1)
        if isinstance(node, AsyncWith):
            print("AsyncWith is not allowed in hacspec.")
            exit(1)
        if isinstance(node, AsyncFor):
            print("AsyncFor is not allowed in hacspec.")
            exit(1)
        if isinstance(node, ClassDef):
            print("Classes are not allowed in hacspec.")
            exit(1)
        if isinstance(node, AsyncFunctionDef):
            print("AsyncFunctionDef is not allowed in hacspec.")
            exit(1)
        if isinstance(node, Raise):
            print("Raise is not allowed in hacspec.")
            exit(1)
        if isinstance(node, Try):
            print("Try is not allowed in hacspec.")
            exit(1)
        if isinstance(node, Assert):
            print("Assert is not allowed in hacspec.")
            exit(1)
        if isinstance(node, Delete):
            print("Delete is not allowed in hacspec.")
            exit(1)
        if isinstance(node, Global):
            print("Global is not allowed in hacspec.")
            exit(1)
        if isinstance(node, Nonlocal):
            print("Global is not allowed in hacspec.")
            exit(1)
        if isinstance(node, Break):
            print("Break is not allowed in hacspec.")
            exit(1)
        if isinstance(node, Continue):
            print("Continue is not allowed in hacspec.")
            exit(1)

        # Disallowed expressions
        if isinstance(node, ListComp):
            print("List comprehensions are not allowed in hacspec.")
            exit(1)
        if isinstance(node, IfExp):
            print("If expressions are not allowed in hacspec.")
            exit(1)

        # List of nodes, read all of them.
        if isinstance(node, list):
            nodes = []
            for x in node:
                nodes.append(self.read(x))
            return AstItem(List, nodes)

        # If we get here, it's not valid.
        print("Spec is not valid using " + str(type(node)))
        exit(1)

    def filter(self, parsed, obj):
        filtered = []
        def rec(x, obj, item=None):
            if isinstance(x, AstItem):
                for y in x.args:
                    if isinstance(x.t, type) and x.t.__name__ == self.to_find:
                        filtered.append(x)
                    rec(y, obj, x)
            elif isinstance(x, list):
                for y in x:
                    rec(y, obj)
            else:
                if isinstance(item.t, type) and item.t.__name__ == self.to_find:
                    if item not in filtered:
                        filtered.append(item)
                # else:
                #     print(item.args)
        for a in parsed.args:
            rec(a, obj)
        return filtered

    def read_objects(self, obj):
        mod = self.ast.body
        if mod is None:
            # ast root has to be Module.
            return []
        if not isinstance(mod, list):
            # The ast module is a list of nodes.
            return []
        self.to_find = obj.__name__
        parsed = self.read(self.ast)
        filtered = self.filter(parsed, obj)
        return filtered


class FileReader():
    def __init__(self, filename):
        self.filename = filename

    def read_functions(self):
        try:
            with open(self.filename, 'r', encoding='utf-8') as py_file:
                code = py_file.read()
                ast = parse(source=code, filename=self.filename)
                reader = AstReader(ast)
                functions = reader.read_objects(FunctionDef)
                return functions
        except:
            print("File is not a valid hacspec. Import is not a local spec.")
            return []
        return []


class FunctionSignature():
    def __init__(self):
        self.fun_name = ""
        self.argtypes = []
        self.returntype = None

    def __str__(self) -> str:
        return self.fun_name + str(self.argtypes) + " -> " + str(self.returntype)

    @staticmethod
    def create(fun_name, args, rt):
        fs = FunctionSignature()
        fs.argtypes = args
        fs.returntype = rt
        fs.fun_name = fun_name
        return fs

    def add_arg(self, arg):
        self.argtypes.append(arg)

    def set_return_type(self, t):
        self.returntype = t

    def get_args(self):
        return self.argtypes

    def get_return_type(self):
        return self.returntype

    def get_fun_name(self):
        return self.fun_name


class Imported():
    def __init__(self, file_dir, ast):
        self.file_dir = file_dir
        self.fsigs = {}
        self.fun_list = []
        self.reader = AstReader(ast)
        self.read_modules()
        self.parse_functions()

    def parse_hacspec_file(self, filename):
        if filename == "speclib":
            # speclib is more complex to parse and it's not a valid hacspec.
            # TODO: We import those functions statically.
            return True
        filename = os.path.join(self.file_dir, filename + ".py")
        reader = FileReader(filename)
        functions = reader.read_functions()
        if len(functions) == 0:
            return False
        self.fun_list += functions
        return True

    def read_modules(self):
        imports = self.reader.read_objects(ImportFrom)
        for imp in imports:
            print("reading functions from import " + imp.args[0])
            if not self.parse_hacspec_file(imp.args[0]):
                print("Only other hacspecs can be imported")
                exit(1)

    def parse_functions(self):
        for f in self.fun_list:
            f = f.get_function_signature()
            self.fsigs[f.get_fun_name()] = f

    def check_function(self, fun, fun_def):
        try:
            fs = self.fsigs[fun]
        except:
            print(fun + " is not a known hacspec function.")
            exit(1)
        # TODO: check fun_def against signature fs
        print(fs)

def main(filename):
    with open(filename, 'r', encoding='utf-8') as py_file:
        file_dir = os.path.dirname(os.path.abspath(filename))
        code = py_file.read()
        ast = parse(source=code, filename=filename)
        imported = Imported(file_dir, ast)
        imported.check_function("chacha20_counter_mode", None)
        # reader = AstReader(ast)
        # functions = reader.read_objects(Call)
        # print(functions)
        # check_ast(ast)


if __name__ == "__main__":
    if len(argv) != 2:
        print("Usage: spec-checker.py <your-hacpsec.py>")
        exit(1)
    main(argv[1])
