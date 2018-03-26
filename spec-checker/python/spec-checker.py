#!/usr/bin/python3

from typed_ast.ast3 import *
from sys import argv
from sys import exit
import builtins
import os

DEBUG_PRINT = True


def print(*args, **kwargs):
    if DEBUG_PRINT:
        builtins.print(*args, **kwargs)


def isTypeAllowed(node, typeList):
    for aType in typeList:
        if isinstance(node, aType):
            return True
    return False

VARIABLES = []

def read(node, allowed=None, prev=[]):
    indent = ''.join(["  " for _ in prev])
    # builtins.print(str(len(prev)) + " " + str(type(node)))
    # indent = "  "
    print(indent + "processing: " + str(type(node)) + " ...")

    # If we have allowed types, check them.
    if not allowed is None and not isTypeAllowed(node, allowed):
        prevNode = str(prev[-1]) if len(prev) > 0 else "start node"
        raise SyntaxError("Operation " + str(node) +
                          " is not allowed in " + prevNode + ".")

    # add node to list of previous nodes
    previous = prev.copy()
    previous.append(node)

    # Read a module.
    if isinstance(node, Module):
        return read(node.body, prev=previous)

    # Check that imports are only from a known list of imports (see ALLOWED_IMPORTS)
    if isinstance(node, ImportFrom):
        print(indent + "ImportFrom: " + node.module)
        return

    if isinstance(node, Tuple):
        names = [read(x, [Name, BinOp, Num, Tuple], previous) for x in node.elts]
        print(indent + "Tuple: " + ', '.join(str(names)))
        return Tuple

    # Normal assignments with types in comments
    if isinstance(node, Assign):
        targets = [str(read(x, [Name, Subscript, Tuple], previous))
                   for x in node.targets]
        print(indent + "targets: " + ', '.join(targets))
        value = read(node.value,
                     [Call, BinOp, Num, Subscript, Name, UnaryOp], previous)
        print(indent + "value: " + str(value))
        type_comment = node.type_comment
        if type_comment:
            print(indent + "type_comment: " + type_comment)
        return
    if isinstance(node, AugAssign):
        read(node.target, prev=previous)
        value = read(node.value,
                     [Call, BinOp, Num, Subscript, Name], previous)
        print(indent + "value: " + str(value))
        return read(node.op, prev=previous)
    if isinstance(node, AnnAssign):
        target = read(node.target, prev=previous)
        print(indent + "target: " + target)
        if node.value:
            value = read(node.value,
                         [Call, BinOp, Num, Subscript, Name, UnaryOp, Tuple], previous)
            print(indent + "value: " + str(value))
        annotation = read(node.annotation, prev=previous)
        print(indent + "type: " + str(annotation))
        return AnnAssign
    if isinstance(node, List):
        for elt in node.elts:
            read(elt, prev=previous)
        return List
    if isinstance(node, Attribute):
        print(indent + "Attribute: " + node.attr)
        read(node.value, prev=previous)
        return Attribute
    # Assignments with types as annotations
    if isinstance(node, AnnAssign):
        raise SyntaxError("AnnAssign is not allowed yet.")

    if isinstance(node, BinOp):
        left = read(node.left,
                    [Num, BinOp, Call, Name, Subscript, UnaryOp], previous)
        op = read(node.op, [Add, Sub, Mult, Div,
                            Mod, Pow, LShift, RShift, BitOr,
                            BitXor, BitAnd, FloorDiv],
                  previous)
        right = read(node.right,
                     [Num, BinOp, Call, Name, Subscript], previous)
        print(indent + str(left) + str(op) + str(right))
        if left is Num and right is Num:
            return Num
        return BinOp

    # Primitive types
    if isinstance(node, Num):
        print(indent + "Num: " + str(node))
        return Num

    if isinstance(node, Name):
        ctx = read(node.ctx, prev=previous)
        print(indent+node.id+" "+str(ctx))
        return node.id

    if isinstance(node, Load):
        return Load
    if isinstance(node, Store):
        return Store
    if isinstance(node, AugStore):
        return AugStore
    if isinstance(node, AugLoad):
        return AugLoad

    # Loops
    if isinstance(node, For):
        read(node.target, prev=previous)
        if node.body:
            read(node.body,  prev=previous)
        if node.orelse:
            read(node.orelse,  prev=previous)
        if node.iter:
            read(node.iter, prev=previous)
        return For

    # Operators
    if isinstance(node, Pow):
        print(indent + "Pow: " + str(node))
        return Pow
    if isinstance(node, Sub):
        print(indent + "Sub: " + str(node))
        return Sub
    if isinstance(node, Mult):
        print(indent + "Mult: " + str(node))
        return Mult
    if isinstance(node, Add):
        print(indent + "Add: " + str(node))
        return Add
    if isinstance(node, Mod):
        print(indent + "Mod: " + str(node))
        return Mod
    if isinstance(node, FloorDiv):
        print(indent + "FloorDiv: " + str(node))
        return FloorDiv
    if isinstance(node, Div):
        print(indent + "Div: " + str(node))
        return FloorDiv
    if isinstance(node, BitXor):
        print(indent + "BitXor: " + str(node))
        return BitXor
    if isinstance(node, RShift):
        print(indent + "RShift: " + str(node))
        return RShift
    if isinstance(node, BitAnd):
        print(indent + "BitAnd: " + str(node))
        return BitAnd
    if isinstance(node, BitOr):
        print(indent + "BitOr: " + str(node))
        return BitOr
    if isinstance(node, UnaryOp):
        print(indent + "UnaryOp: " + str(node))
        return UnaryOp
    if isinstance(node, Compare):
        print(indent + "Compare: " + str(node))
        return Compare
    if isinstance(node, LShift):
        print(indent + "LShift: " + str(node))
        return LShift

    if isinstance(node, BoolOp):
        print(indent + "BoolOp: " + str(node.op))
        for ex in node.values:
            read(ex, prev=previous)
        return BoolOp

    if isinstance(node, Subscript):
        return read(node.value, prev=previous)

    # Functions
    if isinstance(node, FunctionDef):
        print(indent + "Func: " + str(node.name))
        # Check allowed arguments.
        if node.args.args is not None:
            args = [x.arg for x in node.args.args]
            print(indent + "  args: " + ', '.join(args))
        if node.args.defaults is not None:
            defaults = [x.s for x in node.args.defaults]
            print(indent + "  defaults: " + ', '.join(defaults))
        if len(node.args.kwonlyargs) != 0:
            raise SyntaxError("keyword only args are not allowed in hacspec")
        if node.args.vararg is not None:
            raise SyntaxError("varargs are not allowed in hacspec")
        if len(node.args.kw_defaults) != 0:
            raise SyntaxError("keyword defaults are not allowed in hacspec")
        if node.args.kwarg is not None:
            raise SyntaxError("keyword args are not allowed in hacspec")

        # Read function body.
        return read(node.body, prev=previous)
    if isinstance(node, Return):
        return read(node.value, prev=previous)

    if isinstance(node, Call):
        read(node.func, prev=previous)
        if node.args:
            read(node.args, prev=previous)
        return Call

    if isinstance(node, Expr):
        return read(node.value, prev=previous)

    if isinstance(node, If):
        return read(node.test, [Compare, BoolOp, Call], previous)
        return read(node.body, prev=previous)
        return read(node.orelse, prev=previous)

    if isinstance(node, While):
        return read(node.test, [Compare], previous)
        return read(node.body, prev=previous)
        return read(node.orelse, prev=previous)

    # lambdas are only allowed in refine_t statements
    if isinstance(node, Lambda):
        if len(previous) < 4:
            raise SyntaxError(
                "Lambdas are only allowed in `refine` (too short)")
        called_function = previous[-3]
        if isinstance(called_function, Call):
            if isinstance(called_function.func, Name):
                if called_function.func.id == "refine":
                    print(indent + "Refine " + str(previous[-2][0].id))
                    return Lambda
        raise SyntaxError(
            "Lambdas are only allowed in `refine` (you didn't call refine)")

    # Explicitly disallowed statements
    if isinstance(node, With):
        raise SyntaxError("With is not allowed in hacspec.")
    if isinstance(node, AsyncWith):
        raise SyntaxError("AsyncWith is not allowed in hacspec.")
    if isinstance(node, AsyncFor):
        raise SyntaxError("AsyncFor is not allowed in hacspec.")
    if isinstance(node, ClassDef):
        raise SyntaxError("Classes are not allowed in hacspec.")
    if isinstance(node, AsyncFunctionDef):
        raise TypeError("AsyncFunctionDef is not allowed in hacspec.")
    if isinstance(node, Raise):
        raise TypeError("Raise is not allowed in hacspec.")
    if isinstance(node, Try):
        raise TypeError("Try is not allowed in hacspec.")
    if isinstance(node, Assert):
        raise TypeError("Assert is not allowed in hacspec.")
    if isinstance(node, Delete):
        raise TypeError("Delete is not allowed in hacspec.")
    if isinstance(node, Global):
        raise TypeError("Global is not allowed in hacspec.")
    if isinstance(node, Nonlocal):
        raise TypeError("Global is not allowed in hacspec.")
    if isinstance(node, Break):
        raise TypeError("Break is not allowed in hacspec.")
    if isinstance(node, Continue):
        raise TypeError("Continue is not allowed in hacspec.")

    # Disallowed expressions
    if isinstance(node, ListComp):
        raise SyntaxError("List comprehensions are not allowed in hacspec.")
    if isinstance(node, IfExp):
        raise SyntaxError("If expressions are not allowed in hacspec.")

    # List of nodes, read all of them.
    if isinstance(node, list):
        for x in node:
            read(x, prev=previous)
        return

    # If we get here, it's not valid.
    raise TypeError("Spec is not valid using " + str(type(node)))


def check_ast(ast):
    if not isinstance(ast, AST):
        raise TypeError('Expected AST, got %r' % node.__class__.__name__)
    read(ast)

class AstReader():
    def __init__(self, ast):
        self.ast = ast

    def read_objects(self, obj):
        mod = self.ast.body
        if mod is None:
            # ast root has to be Module.
            return []
        if not isinstance(mod, list):
            # The ast module is a list of nodes.
            return []
        objects = []
        for m in mod:
            if isinstance(m, obj):
                objects.append(m)
        return objects



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
        return self.fun_name + str(self.argtypes) + "-> " + str(self.returntype)

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
            # We import those functions statically.
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
            if not self.parse_hacspec_file(imp.module):
                raise TypeError("Only other hacspecs can be imported")

    def parse_functions(self):
        for f in self.fun_list:
            fun_name = f.name
            if f.args.args is not None:
                arg_types = [x.annotation.id for x in f.args.args]
                # print("  arg_types: " + ', '.join(arg_types))
            if f.returns is not None:
                if isinstance(f.returns, Name):
                    rt = f.returns.id
                    # print("  returns: " + rt)
                elif isinstance(f.returns, Subscript):
                    rt = f.returns.slice.value
                    if not isinstance(rt, Tuple):
                        raise SyntaxError("Return types have to be simple types or tuples, not " + str(type(rt)) + ".")
                    rt = [x.id for x in rt.elts]
                    # print("  returns: " + str(rt))
            else:
                raise SyntaxError("Functions must have a return type (use None for void functions).")
            if len(f.decorator_list) != 0:
                raise SyntaxError("Function argument decorators are not supported in hacspec.")
            if len(f.args.defaults) != 0:
                raise SyntaxError("Default arguments are not supported in hacspec.")
            if f.type_comment is not None:
                raise SyntaxError("Type comments on functions are not allowed in hacspec.")
            if len(f.args.kwonlyargs) != 0:
                raise SyntaxError("keyword only args are not allowed in hacspec.")
            if f.args.vararg is not None:
                raise SyntaxError("varargs are not allowed in hacspec")
            if len(f.args.kw_defaults) != 0:
                raise SyntaxError("keyword defaults are not allowed in hacspec")
            if f.args.kwarg is not None:
                raise SyntaxError("keyword args are not allowed in hacspec")
            # TODO: be stricter and check everything.
            self.fsigs[fun_name] = FunctionSignature.create(fun_name, arg_types, rt)

    def check_function(self, fun, fun_def):
        try:
            fs = self.fsigs[fun]
        except:
            raise SyntaxError(fun + " is not a known hacspec function.")
        # TODO: check fun_def against signature fs
        print(fs)

def main(filename):
    with open(filename, 'r', encoding='utf-8') as py_file:
        file_dir = os.path.dirname(os.path.abspath(filename))
        code = py_file.read()
        ast = parse(source=code, filename=filename)
        imported = Imported(file_dir, ast)
        imported.check_function("fmul", None)
        # check_ast(ast)


if __name__ == "__main__":
    if len(argv) != 2:
        print("Usage: spec-checker.py <your-hacpsec.py>")
        exit(1)
    main(argv[1])
