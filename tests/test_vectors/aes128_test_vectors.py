from mypy_extensions import TypedDict
from lib.speclib import *

aes128_test_item = TypedDict('aes128_test', {
    'input_len': int,
    'input': str,
    'key' :  str,
    'nonce_len' :  int,
    'nonce' :  str,
    'counter' : int,
    'output' :  str})

aes128_test = vlarray_t(dict)

aes128_test_vectors = aes128_test([
{   'input_len': 16,
    'input': '6bc1bee22e409f96e93d7e117393172a',
    'key' :  '2b7e151628aed2a6abf7158809cf4f3c',
    'nonce_len': 12,
    'nonce' :  'f0f1f2f3f4f5f6f7f8f9fafb',
    'counter' : 0xfcfdfeff,
    'output' :  '874d6191b620e3261bef6864990db6ce'},
{   'input_len': 16,
    'input': '53696E676C6520626C6F636B206D7367',
    'key' :  'AE6852F8121067CC4BF7A5765577F39E',
    'nonce_len': 16,
    'nonce' :  '00000030000000000000000000000000',
    'counter' : 1,
    'output' :  'E4095D4FB7A7B3792D6175A3261311B8'
},
{   'input_len': 32,
    'input': '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
    'key' :  '7E24067817FAE0D743D6CE1F32539163',
    'nonce_len': 12,
    'nonce' :  '006CB6DBC0543B59DA48D90B',
    'counter' : 1,
    'output' :  '5104A106168A72D9790D41EE8EDAD388EB2E1EFC46DA57C8FCE630DF9141BE28'
}
])
