# speclib interface

from typed_ast.ast3 import *

# speclib class hierarchy
speclib_classes = {
    'vlbytes_t': 'vlarray_t'
}

# function name: [arg list, return value]
speclib = {
    'len': [['vlarray_t'], Num],
    'bytes_t': [[Num], 'bytes_t']
}
