from typing import List
import struct
import base64


def long2intarr(long_int: int) -> List[int]:
    _bytes: List[int] = []
    while long_int:
        long_int, r = divmod(long_int, 256)
        _bytes.insert(0, r)
    return _bytes


def long_to_base64(n: int, mlen: int = 0) -> str:
    bys = long2intarr(n)
    if mlen:
        _len = mlen - len(bys)
        if _len:
            bys = [0] * _len + bys
    data = struct.pack('%sB' % len(bys), *bys)
    if not len(data):
        data = b'\x00'
    s = base64.urlsafe_b64encode(data).rstrip(b'=')
    return s.decode("ascii")
