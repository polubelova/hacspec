from mypy_extensions import TypedDict
from lib.speclib import *

chacha20_test_item = TypedDict('chacha20_test', {
    'input_len': int,
    'input': str,
    'key' :  str,
    'nonce' :  str,
    'counter' : int,
    'output' :  str})

chacha20_test = vlarray_t(dict)

chacha20_test_vectors = chacha20_test([
{   'input_len': 114,
    'input': '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e',
    'key' :  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    'nonce' :  '000000000000004a00000000',
    'counter' : 1,
    'output' :  '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d'}])
