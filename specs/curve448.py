#!/usr/bin/python3

from speclib import *

p448 = 2 ** 448 - 2 ** 224 - 1

felem = refine3(nat, lambda x: x < p448)
felem_t = felem

def to_felem(x:nat_t) -> felem_t:
    return felem(x % p448)

def fadd(x:felem_t, y:felem_t) -> felem_t:
    return to_felem(x + y)

def fsub(x:felem_t, y:felem_t) -> felem_t:
    return to_felem(x - y)

def fmul(x:felem_t, y:felem_t) -> felem_t:
    return to_felem(x * y)

def fsqr(x:felem_t) -> felem_t:
    return to_felem(x * x)

def fexp(x:felem_t, n:nat_t) -> felem_t:
    return to_felem(pow(x, n, p448))

def finv(x:felem_t) -> felem_t:
    return to_felem(pow(x, p448 - 2, p448))

point_t = tuple2(felem_t, felem_t)
scalar_t = bitvector_t(448)

serialized_point_t = bytes_t(56)
serialized_scalar_t = bytes_t(56)

def decodeScalar(s:serialized_scalar_t) -> scalar_t:
    k = vlbytes.copy(s)
    k[0]  &= uint8(252)
    k[55] |= uint8(128)
    return bitvector(bytes.to_nat_le(k), 448)

def decodePoint(u:serialized_point_t) -> point_t:
    b = bytes.to_nat_le(u)
    return ((b % (2 ** 448)) % p448, 1)

def encodePoint(p:point_t) -> serialized_point_t:
    b = fmul(p[0], finv(p[1]))
    return bytes.from_nat_le(b)

def point_add_and_double(q:point_t, nq:point_t, nqp1:point_t) -> tuple2(point_t, point_t):
    (x_1, _) = q
    (x_2, z_2) = nq
    (x_3, z_3) = nqp1
    a  = fadd(x_2, z_2)
    aa = fsqr(a)
    b  = fsub(x_2, z_2)
    bb = fsqr(b)
    e  = fsub(aa, bb)
    c  = fadd(x_3, z_3)
    d  = fsub(x_3, z_3)
    da = fmul(d, a)
    cb = fmul(c, b)
    x_3 = fsqr(fadd(da, cb))
    z_3 = fmul(x_1, fsqr(fsub(da, cb)))
    x_2 = fmul(aa, bb)
    z_2 = fmul(e, fadd(aa, fmul(felem(39081), e)))
    return ((x_2, z_2), (x_3, z_3))

def montgomery_ladder(k:scalar_t, init:point_t) -> point_t:
    p0 : point_t = (1, 0)
    p1 : point_t = init
    for i in range(448):
        if k[447-i] == bit(1):
            (p1, p0) = point_add_and_double(init, p1, p0)
        else:
            (p0, p1) = point_add_and_double(init, p0, p1)
    return(p0)

def scalarmult(s:serialized_scalar_t, p:serialized_point_t) -> serialized_point_t:
    s_ = decodeScalar(s)
    p_ = decodePoint(p)
    r = montgomery_ladder(s_, p_)
    return encodePoint(r)
