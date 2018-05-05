#!/usr/bin/python3

# To run and check this file, you need Python 3 + mypy
# See install instructions at: http://mypy.readthedocs.io/en/latest/getting_started.html
# To typecheck this file: mypy kyber.py
# To run this file: python3 kyber.py

from speclib import *
from keccak import shake128, shake256, sha3_512, sha3_256, shake128_absorb, shake128_squeeze

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
            res_ij = (-mask) & uint16((kyber_q + 1) // 2)
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

kyber_symbytes = 32
kyber_polyveccompressedbytes = kyber_k * 352
kyber_polycompressedbytes = 96
kyber_polybytes = 416
kyber_polyvecbytes = kyber_k * kyber_polybytes

kyber_indcpa_publickeybytes = kyber_polyveccompressedbytes + kyber_symbytes
kyber_indcpa_secretkeybytes = kyber_polyvecbytes
kyber_indcpa_bytes = kyber_polyveccompressedbytes + kyber_polycompressedbytes

def poly_tobytes (a:zqpoly_t) -> bytes_t(kyber_polybytes):
    res = array.create(kyber_polybytes, uint8(0))
    tmp = array.create(8, uint16(0))
    for i in range(kyber_n // 8):
        for j in range(8):
            tmp[j] = (a[8*i+j]) % kyber_q

        res[13*i+0] = uint8(tmp[0] & 0xff)
        res[13*i+1] = uint8((tmp[0] >> 8) | ((tmp[1] & 0x07) << 5))
        res[13*i+2] = uint8((tmp[1] >> 3) & 0xff)
        res[13*i+3] = uint8((tmp[1] >> 11) | ((tmp[2] & 0x3f) << 2))
        res[13*i+4] = uint8((tmp[2] >> 6) | ((tmp[3] & 0x01) << 7))
        res[13*i+5] = uint8((tmp[3] >> 1) & 0xff)
        res[13*i+6] = uint8((tmp[3] >> 9) | ((tmp[4] & 0x0f) << 4))
        res[13*i+7] = uint8((tmp[4] >> 4) & 0xff)
        res[13*i+8] = uint8((tmp[4] >> 12) | ((tmp[5] & 0x7f) << 1))
        res[13*i+9] = uint8((tmp[5] >> 7) | ((tmp[6] & 0x03) << 6))
        res[13*i+10] = uint8((tmp[6] >> 2) & 0xff)
        res[13*i+11] = uint8((tmp[6] >> 10) | ((tmp[7] & 0x1f) << 3))
        res[13*i+12] = uint8(tmp[7] >> 5)
    return res

def poly_frombytes (a:bytes_t(kyber_polybytes)) -> zqpoly_t:
    res = array.create(kyber_n, zqelem_t(0))

    for i in range(kyber_n // 8):
        res[8*i+0] = zqelem(int(uint16(a[13*i+0]) | ((uint16(a[13*i+1]) & uint16(0x1f)) << 8)))
        res[8*i+1] = zqelem(int((uint16(a[13*i+1]) >> 5) | (uint16(a[13*i+2]) << 3) | ((uint16(a[13*i+3]) & uint16(0x03)) << 11)))
        res[8*i+2] = zqelem(int((uint16(a[13*i+3]) >> 2) | ((uint16(a[13*i+4]) & uint16(0x7f)) << 6)))
        res[8*i+3] = zqelem(int((uint16(a[13*i+4]) >> 7) | (uint16(a[13*i+5]) << 1) | ((uint16(a[13*i+6]) & uint16(0x0f)) << 9)))
        res[8*i+4] = zqelem(int((uint16(a[13*i+6]) >> 4) | (uint16(a[13*i+7]) << 4) | ((uint16(a[13*i+8]) & uint16(0x01)) << 12)))
        res[8*i+5] = zqelem(int((uint16(a[13*i+8]) >> 1) | ((uint16(a[13*i+9]) & uint16(0x3f)) << 7)))
        res[8*i+6] = zqelem(int((uint16(a[13*i+9]) >> 6) | (uint16(a[13*i+10]) << 2) | ((uint16(a[13*i+11]) & uint16(0x07)) << 10)))
        res[8*i+7] = zqelem(int((uint16(a[13*i+11]) >> 3) | (uint16(a[13*i+12]) << 5)))
    return res

def poly_compress_vec(a:zqpoly_t) -> bytes_t(352):
    res = array.create(352, uint8(0))
    tmp = array.create(8, uint16(0))

    for j in range(kyber_n // 8):
        for k in range(8):
            tmp_k = (int(uint32((a[8*j+k]) % kyber_q) << 11) + kyber_q // 2) // kyber_q
            tmp[k] = tmp_k & 0x7ff

        res[11*j+0] = uint8(tmp[0] & 0xff)
        res[11*j+1] = uint8((tmp[0] >> 8) | ((tmp[1] & 0x1f) << 3))
        res[11*j+2] = uint8((tmp[1] >> 5) | ((tmp[2] & 0x03) << 6))
        res[11*j+3] = uint8((tmp[2] >> 2) & 0xff)
        res[11*j+4] = uint8((tmp[2] >> 10) | ((tmp[3] & 0x7f) << 1))
        res[11*j+5] = uint8((tmp[3] >> 7) | ((tmp[4] & 0x0f) << 4))
        res[11*j+6] = uint8((tmp[4] >> 4) | ((tmp[5] & 0x01) << 7))
        res[11*j+7] = uint8((tmp[5] >> 1) & 0xff)
        res[11*j+8] = uint8((tmp[5] >> 9) | ((tmp[6] & 0x3f) << 2))
        res[11*j+9] = uint8((tmp[6] >> 6) | ((tmp[7] & 0x07) << 5))
        res[11*j+10] = uint8(tmp[7] >> 3)
    return res

def poly_decompress_vec(a:bytes_t(352)) -> zqpoly_t:
    res = array.create(kyber_n, zqelem_t(0))

    for j in range(kyber_n // 8):
      res[8*j+0] = zqelem(int((((uint32(a[11*j+0]) | ((uint32(a[11*j+1]) & uint32(0x07)) << 8)) * uint32(kyber_q)) + uint32(1024)) >> 11))
      res[8*j+1] = zqelem(int(((((uint32(a[11*j+1]) >> 3) | ((uint32(a[11*j+2]) & uint32(0x3f)) << 5)) * uint32(kyber_q)) + uint32(1024)) >> 11))
      res[8*j+2] = zqelem(int(((((uint32(a[11*j+2]) >> 6) | ((uint32(a[11*j+3]) & uint32(0xff)) << 2) | ((uint32(a[11*j+4]) & uint32(0x01)) << 10)) * uint32(kyber_q)) + uint32(1024)) >> 11))
      res[8*j+3] = zqelem(int(((((uint32(a[11*j+4]) >> 1) | ((uint32(a[11*j+5]) & uint32(0x0f)) << 7)) * uint32(kyber_q)) + uint32(1024)) >> 11))
      res[8*j+4] = zqelem(int(((((uint32(a[11*j+5]) >> 4) | ((uint32(a[11*j+6]) & uint32(0x7f)) << 4)) * uint32(kyber_q)) + uint32(1024)) >> 11))
      res[8*j+5] = zqelem(int(((((uint32(a[11*j+6]) >> 7) | ((uint32(a[11*j+7]) & uint32(0xff)) << 1) | ((uint32(a[11*j+8]) & uint32(0x03)) <<  9)) * uint32(kyber_q)) + uint32(1024)) >> 11))
      res[8*j+6] = zqelem(int(((((uint32(a[11*j+8]) >> 2) | ((uint32(a[11*j+9]) & uint32(0x1f)) << 6)) * uint32(kyber_q)) + uint32(1024)) >> 11))
      res[8*j+7] = zqelem(int(((((uint32(a[11*j+9]) >> 5) | ((uint32(a[11*j+10]) & uint32(0xff)) << 3)) * uint32(kyber_q)) + uint32(1024)) >> 11))
    return res

def poly_compress(a:zqpoly_t) -> bytes_t(kyber_polycompressedbytes):
    res = array.create(kyber_polycompressedbytes, uint8(0))
    tmp = array.create(8, uint32(0))
    k = 0

    for i in range(kyber_n // 8):
        for j in range(8):
            tmp[j] = (((a[i*8+j] << 3) + kyber_q // 2) // kyber_q) & 7

        res[k] = uint8(tmp[0] | (tmp[1] << 3) | (tmp[2] << 6))
        res[k+1] = uint8((tmp[2] >> 2) | (tmp[3] << 1) | (tmp[4] << 4) | (tmp[5] << 7))
        res[k+2] = uint8((tmp[5] >> 1) | (tmp[6] << 2) | (tmp[7] << 5))
        k = k + 3
    return res

def poly_decompress(a:bytes_t(kyber_polycompressedbytes)) -> zqpoly_t:
    res = array.create(kyber_n, zqelem_t(0))
    k = 0

    for i in range(kyber_n // 8):
        res[8*i+0] = zqelem(int(((uint16(a[k+0]) & uint16(7)) * uint16(kyber_q)) + uint16(4)) >> 3)
        res[8*i+1] = zqelem(int((((uint16(a[k+0]) >> 3) & uint16(7)) * uint16(kyber_q)) + uint16(4)) >> 3)
        res[8*i+2] = zqelem(int((((uint16(a[k+0]) >> 6) | ((uint16(a[k+1]) << 2) & uint16(4))) * uint16(kyber_q)) + uint16(4)) >> 3)
        res[8*i+3] = zqelem(int((((uint16(a[k+1]) >> 1) & uint16(7)) * uint16(kyber_q)) + uint16(4)) >> 3)
        res[8*i+4] = zqelem(int((((uint16(a[k+1]) >> 4) & uint16(7)) * uint16(kyber_q)) + uint16(4)) >> 3)
        res[8*i+5] = zqelem(int((((uint16(a[k+1]) >> 7) | ((uint16(a[k+2]) << 1) & uint16(6))) * uint16(kyber_q)) + uint16(4)) >> 3)
        res[8*i+6] = zqelem(int((((uint16(a[k+2]) >> 2) & uint16(7)) * uint16(kyber_q)) + uint16(4)) >> 3)
        res[8*i+7] = zqelem(int((((uint16(a[k+2]) >> 5)) * uint16(kyber_q)) + uint16(4)) >> 3)
        k = k + 3
    return res

def polyvec_tobytes (a:zqpolyvec_t) -> bytes_t(kyber_polyvecbytes):
    res = array.create(kyber_polyvecbytes, uint8(0))
    for i in range(kyber_k):
        r_i = poly_tobytes(a[i])
        res[i*kyber_polybytes:(i+1)*kyber_polybytes] = r_i
    return res

def polyvec_frombytes (a:bytes_t(kyber_polyvecbytes)) -> zqpolyvec_t:
    res = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))

    for i in range(kyber_k):
        res[i] = poly_frombytes(a[i*kyber_polybytes:(i+1)*kyber_polybytes])
    return res

def polyvec_compress(a:zqpolyvec_t) -> bytes_t(kyber_polyveccompressedbytes):
    res = array.create(kyber_polyveccompressedbytes, uint8(0))

    for i in range(kyber_k):
        res[i*352:(i+1)*352] = poly_compress_vec(a[i])
    return res

def polyvec_decompress(a:bytes_t(kyber_polyveccompressedbytes)) -> zqpolyvec_t:
    res = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))

    for i in range(kyber_k):
        res[i] = poly_decompress_vec(a[i*352:(i+1)*352])
    return res

def pack_sk(sk:zqpolyvec_t) -> bytes_t(kyber_indcpa_secretkeybytes):
    return polyvec_tobytes(sk)

def unpack_sk(packedsk:bytes_t(kyber_indcpa_secretkeybytes)) -> zqpolyvec_t:
    return polyvec_frombytes(packedsk)

def pack_pk(pk:zqpolyvec_t, seed:bytes_t(32)) -> bytes_t(kyber_indcpa_publickeybytes):
    res = array.create(kyber_indcpa_publickeybytes, uint8(0))
    res[0:kyber_polyveccompressedbytes] = polyvec_compress(pk)
    res[kyber_polyveccompressedbytes:kyber_indcpa_publickeybytes] = seed
    return res

def unpack_pk(packedpk:bytes_t(kyber_indcpa_publickeybytes)) -> (zqpolyvec_t, bytes_t(32)):
    pk = polyvec_decompress(packedpk[0:kyber_polyveccompressedbytes])
    seed = packedpk[kyber_polyveccompressedbytes:kyber_indcpa_publickeybytes]
    return (pk, seed)

def pack_ciphertext(b:zqpolyvec_t, v:zqpoly_t) -> bytes_t(kyber_indcpa_bytes):
    res = array.create(kyber_indcpa_bytes, uint8(0))
    res[0:kyber_polyveccompressedbytes] = polyvec_compress(b)
    res[kyber_polyveccompressedbytes:kyber_indcpa_bytes] = poly_compress(v)
    return res

def unpack_ciphertext(c:bytes_t(kyber_indcpa_bytes)) -> (zqpolyvec_t, zqpoly_t):
    u = polyvec_decompress(c[0:kyber_polyveccompressedbytes])
    v = poly_decompress(c[kyber_polyveccompressedbytes:kyber_indcpa_bytes])
    return (u, v)

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
def kyber_cpapke_keypair(coins:bytes_t(32)) -> (bytes_t(kyber_indcpa_publickeybytes), bytes_t(kyber_indcpa_secretkeybytes)):
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

    sk = pack_sk(shat)
    pk = pack_pk(t, rho)

    return (pk, sk)

#(u, v)
def kyber_cpapke_encrypt(m:bytes_t(32), packedpk:bytes_t(kyber_indcpa_publickeybytes), coins:bytes_t(32)) -> bytes_t(kyber_indcpa_bytes):
    n = uint8(0)
    r = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))
    e1 = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))
    uhat = array.create(kyber_k, array.create(kyber_n, zqelem_t(0)))
    vhat = array.create(kyber_n, zqelem(0))
    At = array.create(kyber_k, array.create(kyber_k, array.create(kyber_n, zqelem_t(0))))

    t, rho = unpack_pk(packedpk)

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
    c = pack_ciphertext(u, v)

    return c

def kyber_cpapke_decrypt(c:bytes_t(kyber_indcpa_bytes), sk:bytes_t(kyber_indcpa_secretkeybytes)) -> bytes_t(32):
    dhat = array.create(kyber_n, zqelem(0))

    u, v = unpack_ciphertext(c)
    s = unpack_sk(sk)

    uhat = bit_reversed_polyvec(zqpolyvec_ntt(u))

    for i in range(kyber_k):
        dhat = zqpoly_add(dhat, zqpoly_pointwise_mul(s[i], uhat[i]))

    d = zqpoly_invntt(bit_reversed_poly(dhat))
    d = zqpoly_sub(v, d)
    msg = poly_tomsg(d)

    return msg

kyber_publickeybytes = kyber_indcpa_publickeybytes
kyber_secretkeybytes = kyber_indcpa_secretkeybytes + kyber_indcpa_publickeybytes + 2 * kyber_symbytes
kyber_ciphertextbytes = kyber_indcpa_bytes

def crypto_kem_keypair(keypaircoins:bytes_t(32), coins:bytes_t(32)) -> (bytes_t(kyber_publickeybytes), bytes_t(kyber_secretkeybytes)):
    sk = array.create(kyber_secretkeybytes, uint8(0))
    pk, sk1 = kyber_cpapke_keypair(keypaircoins)
    sk[0:kyber_indcpa_secretkeybytes] = sk1
    sk[kyber_indcpa_secretkeybytes:(kyber_indcpa_secretkeybytes + kyber_indcpa_publickeybytes)] = pk
    sk[(kyber_indcpa_secretkeybytes + kyber_indcpa_publickeybytes):(kyber_secretkeybytes - kyber_symbytes)] = sha3_256(kyber_publickeybytes, pk)
    sk[(kyber_secretkeybytes - kyber_symbytes):kyber_secretkeybytes] = coins
    return (pk, sk)

def crypto_kem_enc(pk:bytes_t(kyber_publickeybytes), msgcoins:bytes_t(32)) -> (bytes_t(kyber_ciphertextbytes), bytes_t(32)):
    buf = array.create(2 * kyber_symbytes, uint8(0))

    buf[0:kyber_symbytes] = sha3_256(32, msgcoins)
    buf[kyber_symbytes:(2 * kyber_symbytes)] = sha3_256(kyber_publickeybytes, pk)

    kr = sha3_512(2 * kyber_symbytes, buf)
    ct = kyber_cpapke_encrypt(buf[0:kyber_symbytes], pk, kr[kyber_symbytes:(2*kyber_symbytes)])
    kr[kyber_symbytes:(2*kyber_symbytes)] = sha3_256(kyber_ciphertextbytes, ct)
    ss = sha3_256(2*kyber_symbytes, kr)
    return (ct, ss)

def crypto_kem_dec(ct:bytes_t(kyber_ciphertextbytes), sk:bytes_t(kyber_secretkeybytes)) -> bytes_t(32):
    buf = array.create(2 * kyber_symbytes, uint8(0))
    pk = sk[kyber_indcpa_secretkeybytes:(kyber_indcpa_secretkeybytes + kyber_indcpa_publickeybytes)]
    sk1 = sk[0:kyber_indcpa_secretkeybytes]
    buf[0:kyber_symbytes] = kyber_cpapke_decrypt(ct, sk1)
    buf[kyber_symbytes:(2 * kyber_symbytes)] = sk[(kyber_indcpa_secretkeybytes + kyber_indcpa_publickeybytes):(kyber_secretkeybytes - kyber_symbytes)]
    kr = sha3_512(2 * kyber_symbytes, buf)
    cmp1 = kyber_cpapke_encrypt(buf[0:kyber_symbytes], pk, kr[kyber_symbytes:(2 * kyber_symbytes)])
    kr[kyber_symbytes:(2 * kyber_symbytes)] = sha3_256(kyber_ciphertextbytes, ct)
    if (cmp1 == ct):
        kr[0:kyber_symbytes] = kr[0:kyber_symbytes]
    else:
        kr[0:kyber_symbytes] = sk[(kyber_secretkeybytes - kyber_symbytes):kyber_secretkeybytes]
    ss = sha3_256(2 * kyber_symbytes, kr)
    return ss
