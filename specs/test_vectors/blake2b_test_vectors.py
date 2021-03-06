from mypy_extensions import TypedDict
from speclib import array

blake2b_test = TypedDict('blake2b_test', {
    'data': str,
    'key': str,
    'nn': int,
    'output': str
    })

blake2b_test_vectors = array([
    {'data': '616263',
    'key': '',
    'nn': 64,
    'output': 'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923'}
])
