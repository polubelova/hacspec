#!/usr/bin/python3

# To run and check this file, you need Python 3 + mypy
# See install instructions at: http://mypy.readthedocs.io/en/latest/getting_started.html
# To typecheck this file: mypy kyber.py
# To run this file: python3 kyber.py

from speclib import *
from keccak import shake128, shake256, sha3_512, shake128_absorb, shake128_squeeze

kyber_q   = 7681
kyber_n   =  256

kyber_k   =    3 # How do we want to handle different values?
kyber_eta =    4 # How do we want to handle different values?

kyber_dt  =   11
kyber_du  =   11
kyber_dv  =    3

zqelem   = refine3(nat, lambda x: x < kyber_q)
zqelem_t = zqelem

zqpoly_t    = refine3(array[zqelem_t], lambda x: array.length(x) == kyber_n)
zqpolyvec_t = refine3(array[zqpoly_t], lambda x: array.length(x) == kyber_k)

omega     = zqelem(3844)
psi       = zqelem(62)
n_inv     = zqelem(7651)
psi_inv   = zqelem(1115)
omega_inv = zqelem(6584)

def to_zqelem(x:nat_t) -> zqelem_t:
    return zqelem(x % kyber_q)

def zqadd(a:zqelem_t, b:zqelem_t) -> zqelem_t:
    return to_zqelem(a + b)

def zqsub(a:zqelem_t, b:zqelem_t) -> zqelem_t:
    return to_zqelem(a + kyber_q - b)

def zqmul(a:zqelem_t, b:zqelem_t) -> zqelem_t:
    return to_zqelem(a * b)

def zqexp(a:zqelem_t, exp:nat_t) -> zqelem_t:
    return to_zqelem(pow(a, exp, kyber_q))

#poly
def zqpoly_add(p:zqpoly_t, q:zqpoly_t) -> zqpoly_t:
    np = array.create(kyber_n, zqelem(0))
    for i in range(kyber_n):
        np[i] = zqadd(p[i], q[i])
    return np

def zqpoly_sub(p:zqpoly_t, q:zqpoly_t) -> zqpoly_t:
    np = array.create(kyber_n, zqelem(0))
    for i in range(kyber_n):
        np[i] = zqsub(p[i], q[i])
    return np

def zqpoly_pointwise_mul(p:zqpoly_t, q:zqpoly_t) -> zqpoly_t:
    np = array.create(kyber_n, zqelem(0))
    for i in range(kyber_n):
        np[i] = zqmul(p[i], q[i])
    return np

def zqpoly_ntt(p:zqpoly_t) -> zqpoly_t:
    np = array.create(kyber_n, zqelem(0))
    for i in range(kyber_n):
        for j in range(kyber_n):
            np[i] = zqadd(np[i], zqmul(zqmul(zqexp(psi, j), p[j]), zqexp(omega, i * j)))
    return np

def zqpoly_invntt(p:zqpoly_t) -> zqpoly_t:
    np = array.create(kyber_n, zqelem(0))
    for i in range(kyber_n):
        for j in range(kyber_n):
            np[i] = zqadd(np[i], zqmul(p[j], zqexp(omega_inv, i * j)))
        np[i] = zqmul(np[i], zqmul(n_inv, zqexp(psi_inv, i)))
    return np

def zqpoly_mul(p:zqpoly_t, q:zqpoly_t) -> zqpoly_t:
    return zqpoly_invntt(zqpoly_pointwise_mul(zqpoly_ntt(p), zqpoly_ntt(q)))

# just for debugging
def zqpoly_mul_schoolbook(p:zqpoly_t, q:zqpoly_t) -> zqpoly_t:
    s = array.create(kyber_n + kyber_n, zqelem(0))
    for i in range(kyber_n):
        for j in range(kyber_n):
            s[i+j] = zqadd(s[i+j], zqmul(p[i], q[j]))
    high = s[kyber_n:(kyber_n + kyber_n)]
    low = s[0:kyber_n]
    r = zqpoly_sub(low, high)
    return r

#polyvec
def zqpolyvec_add(a:zqpolyvec_t, b:zqpolyvec_t) -> zqpolyvec_t:
    r = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))
    for i in range(kyber_k):
        r[i] = zqpoly_add(a[i], b[i])
    return r

def zqpolyvec_ntt(r:zqpolyvec_t) -> zqpolyvec_t:
    for i in range(kyber_k):
        r[i] = zqpoly_ntt(r[i])
    return r

def zqpolyvec_invntt(r:zqpolyvec_t) -> zqpolyvec_t:
    res = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))
    for i in range(kyber_k):
        res[i] = zqpoly_invntt(r[i])
    return res

#kyber
def bit_reverse(x:uint8_t) -> uint8_t:
    y = uint8(0)
    for i in range(8):
        y += (x & uint8(1)) << (7 - i)
        x = x >> 1
    return y

def bit_reversed_poly(p:zqpoly_t) -> zqpoly_t:
    res = array.create(kyber_n, zqelem_t(0))
    for i in range(kyber_n):
        i_new = bit_reverse(uint8(i))
        res[i] = p[int(i_new)]
    return res

def bit_reversed_polyvec(p:zqpolyvec_t) -> zqpolyvec_t:
    res = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))
    for j in range(kyber_k):
        res[j] = bit_reversed_poly(p[j])
    return res


def msg_topoly(m:bytes_t(32)) -> zqpoly_t:
    res = array.create(kyber_n, zqelem_t(0))
    for i in range(32):
        for j in range(8):
            mask = (uint16(m[i]) >> j) & uint16(1)
            mask = (uint16(2 ** 16 - 1) - mask + uint16(1)) #the ~ operator doesn't work here :/
            res_ij = mask & uint16((kyber_q + 1) // 2)
            res[8 * i + j] = zqelem(int(res_ij))
    return res

def poly_tomsg(p:zqpoly_t) -> bytes_t(32):
    msg = array.create(32, uint8(0))
    for i in range(32):
        for j in range(8):
            t = uint16(p[8 * i + j]) << 1
            t = (int(t) + kyber_q // 2) // kyber_q
            t = uint16(t) & uint16(1)
            t = uint8(t)
            msg[i] = msg[i] | (t << j);
    return msg


def bytesToBits(b:vlbytes_t) -> bitvector_t:
    return bitvector(bytes.to_nat_le(b), 8 * array.length(b))

def cbd(buf:bytes_t(64 * kyber_eta)) -> zqpoly_t:
    beta = bytesToBits(buf)
    res = array.create(kyber_n, zqelem(0))
    for i in range(kyber_n):
        a = nat(0)
        b = nat(0)
        for j in range(kyber_eta):
            a = a + bit.to_int(beta[2 * i * kyber_eta + j])
        for j in range(kyber_eta):
            b = b + bit.to_int(beta[2 * i * kyber_eta + kyber_eta + j])
        res[i] = zqsub(zqelem(a), zqelem(b))
    return res

#cbd(prf(seed, nonce)), prf = shake256
def poly_getnoise(seed:bytes_t(32), nonce:uint8_t) -> zqpoly_t:
    extseed = array.create(32 + 1, uint8(0))
    extseed[0:32] = seed
    extseed[32] = nonce
    buf = shake256(32 + 1, extseed, kyber_eta * kyber_n // 4)
    r = cbd(buf)
    return r

SHAKE128_RATE = 168

#parse(xof(p || a || b)), xof = shake128
def genAij(seed:bytes_t(32), a:uint8_t, b:uint8_t) -> zqpoly_t:
    res = array.create(kyber_n, zqelem(0))

    extseed = array.create(32 + 2, uint8(0))
    extseed[0:32] = seed
    extseed[32] = a
    extseed[33] = b

    maxnblocks = 4
    nblocks = maxnblocks
    state = shake128_absorb(32 + 2, extseed)
    buf = shake128_squeeze(state, SHAKE128_RATE * nblocks)

    i = 0 #pos
    j = 0 #ctr
    while (j < kyber_n):
        d = uint16(buf[i]) | (uint16(buf[i + 1]) << 8)
        d = int(d & uint16(0x1fff))
        if (d < kyber_q):
            res[j] = zqelem(d)
            j = j + 1
        i = i + 2
        if (i > SHAKE128_RATE * nblocks - 2):
            nblocks = 1
            buf = shake128_squeeze(state, SHAKE128_RATE * nblocks)
            i = 0
    return res

#(s, t, rho)
def kyber_cpapke_keypair(coins:bytes_t(32)) -> (zqpolyvec_t, zqpolyvec_t, bytes_t(32)):
    rhosigma = sha3_512(array.length(coins), coins)
    rho = rhosigma[0:32]
    sigma = rhosigma[32:64]

    n = uint8(0)
    s = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))
    e = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))
    that = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))
    A = array.create(kyber_k, array.create(kyber_k, array.create(kyber_n, zqelem_t(0))))

    for i in range(kyber_k):
        A[i] = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))
        for j in range(kyber_k):
            A[i][j] = array.create(kyber_n, zqelem_t(0))

    for i in range(kyber_k):
        for j in range(kyber_k):
            A[i][j] = genAij(rho, uint8(j), uint8(i))

    for i in range(kyber_k):
        s[i] = poly_getnoise(sigma, n)
        n += uint8(1)

    for i in range(kyber_k):
        e[i] = poly_getnoise(sigma, n)
        n += uint8(1)

    shat = bit_reversed_polyvec(zqpolyvec_ntt(s))

    # that = A * shat
    for i in range(kyber_k):
        for j in range(kyber_k):
            that[i] = zqpoly_add(that[i], zqpoly_pointwise_mul(A[i][j], shat[j]))

    t = zqpolyvec_invntt(bit_reversed_polyvec(that))
    t = zqpolyvec_add(t, e)

    return (shat, t, rho)

#(u, v)
def kyber_cpapke_encrypt(m:bytes_t(32), t:zqpolyvec_t, rho:bytes_t(32), coins:bytes_t(32)) -> (zqpolyvec_t, zqpoly_t):
    n = uint8(0)
    r = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))
    e1 = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))
    uhat = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))
    vhat = array.create(kyber_n, zqelem(0))
    At = array.create(kyber_k, array.create(kyber_k, array.create(kyber_n, zqelem_t(0))))

    for i in range(kyber_k):
        At[i] = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))
        for j in range(kyber_k):
            At[i][j] = array.create(kyber_n, zqelem_t(0))

    for i in range(kyber_k):
        for j in range(kyber_k):
            At[i][j] = genAij(rho, uint8(i), uint8(j))

    for i in range(kyber_k):
        r[i] = poly_getnoise(coins, n)
        n += uint8(1)

    for i in range(kyber_k):
        e1[i] = poly_getnoise(coins, n)
        n += uint8(1)

    e2 = poly_getnoise(coins, n)

    rhat = bit_reversed_polyvec(zqpolyvec_ntt(r))

    for i in range(kyber_k):
        for j in range(kyber_k):
            uhat[i] = zqpoly_add(uhat[i], zqpoly_pointwise_mul(At[i][j], rhat[j]))

    u = zqpolyvec_invntt(bit_reversed_polyvec(uhat))
    u = zqpolyvec_add(u, e1)

    that = bit_reversed_polyvec(zqpolyvec_ntt(t))

    for i in range(kyber_k):
        vhat = zqpoly_add(vhat, zqpoly_pointwise_mul(that[i], rhat[i]))

    v = zqpoly_invntt(bit_reversed_poly(vhat))
    v = zqpoly_add(zqpoly_add(v, e2), msg_topoly(m))

    return (u, v)

def kyber_cpapke_decrypt(u:zqpolyvec_t, v:zqpoly_t, s:zqpolyvec_t) -> bytes_t(32):
    dhat = array.create(kyber_n, zqelem(0))

    uhat = bit_reversed_polyvec(zqpolyvec_ntt(u))

    for i in range(kyber_k):
        dhat = zqpoly_add(dhat, zqpoly_pointwise_mul(s[i], uhat[i]))

    d = zqpoly_invntt(bit_reversed_poly(dhat))
    d = zqpoly_sub(v, d)
    msg = poly_tomsg(d)

    return msg
