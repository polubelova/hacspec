# speclib interface

from typed_ast.ast3 import *

# speclib class hierarchy
speclib_classes = {
    'vlbytes_t': 'vlarray_t',
    '_vlarray': 'array',
    'bytes_t': 'array',
    '_uintn': 'int',
}

# function name: [arg list, return value]
speclib = {
    'len': [['vlarray_t'], Num],
    'bytes_t': [[Num], 'bytes_t'],
    'array.create': [[Num], 'vlarray_t'],
    'array.copy': [['vlarray_t'], 'vlarray_t'],
    'bytes.from_uint64_le': [['uint64_t'], 'vlarray[uint8]'],
    'uint64': [[Num], 'uint64_t'],
    'uint128.to_int': [['_uintn'], Num],
    'bytes.to_uint128_le': [['vlarray[uint8]'], 'uint128_t'],
}
