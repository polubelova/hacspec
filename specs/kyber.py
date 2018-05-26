#!/usr/bin/python3

# To run and check this file, you need Python 3 + mypy
# See install instructions at: http://mypy.readthedocs.io/en/latest/getting_started.html
# To typecheck this file: mypy kyber.py
# To run this file: python3 kyber.py

from lib.speclib import *
from specs.keccak import *
from math import floor

kyber_q   = 7681
kyber_n   =  256

variant_k   = refine(int, lambda x: x == 2 or x == 3 or x == 4)
variant_eta = refine(int, lambda x: x == 5 or x == 4 or x == 3)

zqelem_t = nat_mod_t(kyber_q)
def zqelem(n:nat):
    return nat_mod(n,kyber_q)

zqpoly_t = vector_t(zqelem_t,kyber_n)

def zqpolyvec_t(kyber_k:variant_k):
    return matrix_t(zqelem_t,kyber_n,kyber_k)

kyber_dt  =   11
kyber_du  =   11
kyber_dv  =    3

omega     = zqelem(3844)
psi       = zqelem(62)
n_inv     = zqelem(7651)
psi_inv   = zqelem(1115)
omega_inv = zqelem(6584)

#NTTs and bitreversed order

@typechecked
def zqpoly_ntt(p:zqpoly_t) -> zqpoly_t:
    np = array.create(kyber_n, zqelem(0))
    for i in range(kyber_n):
        for j in range(kyber_n):
            np[i] += (((psi ** j) * p[j]) * (omega ** (i * j)))
    return vector(np)

@typechecked
def zqpoly_invntt(p:zqpoly_t) -> zqpoly_t:
    np = array.create(kyber_n, zqelem(0))
    for i in range(kyber_n):
        for j in range(kyber_n):
            np[i] += (p[j] * (omega_inv ** (i * j)))
        np[i] *= n_inv * (psi_inv ** i)
    return vector(np)

@contract3(lambda kyber_k, r: array.length(r) == kyber_k,
           lambda kyber_k, r, res: array.length(res) == kyber_k)
@typechecked
def zqpolyvec_ntt(kyber_k:variant_k, r:zqpolyvec_t) -> zqpolyvec_t:
    res = array.create(kyber_k, array.create(kyber_n, zqelem(0)))
    for i in range(kyber_k):
        res[i] = zqpoly_ntt(r[i])
    return matrix(res)

@contract3(lambda kyber_k, r: array.length(r) == kyber_k,
           lambda kyber_k, r, res: array.length(res) == kyber_k)
@typechecked
def zqpolyvec_invntt(kyber_k:variant_k, r:zqpolyvec_t) -> zqpolyvec_t:
    res = array.create(kyber_k, array.create(kyber_n, zqelem(0)))
    for i in range(kyber_k):
        res[i] = zqpoly_invntt(r[i])
    return matrix(res)

@typechecked
def bit_reverse(x:uint8_t) -> uint8_t:
    y = uint8(0)
    for i in range(8):
        y += (x & uint8(1)) << (7 - i)
        x = x >> 1
    return y

@typechecked
def bit_reversed_poly(p:zqpoly_t) -> zqpoly_t:
    res = array.create(kyber_n, zqelem(0))
    for i in range(kyber_n):
        i_new = bit_reverse(uint8(i))
        res[i] = p[int(i_new)]
    return vector(res)

@contract3(lambda kyber_k, p: array.length(p) == kyber_k,
           lambda kyber_k, p, res: array.length(res) == kyber_k)
@typechecked
def bit_reversed_polyvec(kyber_k:variant_k, p:zqpolyvec_t) -> zqpolyvec_t:
    res = array.create(kyber_k, array.create(kyber_n, zqelem(0)))
    for j in range(kyber_k):
        res[j] = bit_reversed_poly(p[j])
    return matrix(res)

#Encoding and decoding

@typechecked
def bytesToBits(b:vlbytes_t) -> bitvector_t:
    return bitvector(bytes.to_nat_le(b), 8 * array.length(b))

@typechecked
def bitsToBytes(b:bitvector_t) -> bytes_t:
    resLen = b.bits // 8
    res = array.create(resLen, uint8(0))
    for i in range(resLen):
        res_i = uint8(0)
        for j in range(8):
            res_i = res_i + (uint8(b[i*8 +j]) << j)
        res[i] = res_i
    return res

@typechecked
def decode(l:nat, b:bytes_t) -> [int]: #array.length(b) == 32 * l
    res = array.create(kyber_n, 0)
    beta = bytesToBits(b)
    for i in range(kyber_n):
        f_i = uint16(0)
        for j in range(l):
            f_i = f_i + (uint16(beta[i * l + j]) << j)
        res[i] = int(f_i)
    return res

@typechecked
def encode(l:nat, p:[int]) -> bytes_t: #array.length(res) == 32 * l
    res = array.create(32 * l, uint8(0))
    beta = bytesToBits(res)
    for i in range(kyber_n):
        for j in range(l):
            v = (p[i] >> j) & 1
            beta = intn.set_bit(beta, i*l+j, v)
    return (bitsToBytes(beta))

#Compression and Decompression

def compress(x:zqelem_t, d:int) -> int:
    x = nat_mod.to_int(x)
    d2 = 2 ** d
    res = floor (d2 / kyber_q * x + 1 /2)
    return res % d2

def decompress(x:int, d:int) -> zqelem_t:
    d2 = 2 ** d
    res = floor (kyber_q / d2 * x + 1/2)
    return zqelem(res)

kyber_symbytes = 32
kyber_polycompressedbytes = 96
kyber_polybytes = 416

@typechecked
def kyber_polyveccompressedbytes(kyber_k:variant_k):
    return (kyber_k * 352)

@typechecked
def kyber_polyvecbytes(kyber_k:variant_k):
    return (kyber_k * kyber_polybytes)

@typechecked
def kyber_indcpa_publickeybytes(kyber_k:variant_k):
    return (kyber_polyveccompressedbytes(kyber_k) + kyber_symbytes)

@typechecked
def kyber_indcpa_secretkeybytes(kyber_k:variant_k):
    return kyber_polyvecbytes(kyber_k)

@typechecked
def kyber_indcpa_bytes(kyber_k:variant_k):
    return (kyber_polyveccompressedbytes(kyber_k) + kyber_polycompressedbytes)

symbytes_t = bytes_t(kyber_symbytes)


#decode1(decompress(m, 1))
@typechecked
def msg_to_poly(m:symbytes_t) -> zqpoly_t:
    res = decode(1, m)
    for i in range(kyber_n):
        res[i] = decompress(res[i], 1)
    return vector(res)

#encode1(compress(p, 1))
@typechecked
def poly_to_msg(p:zqpoly_t) -> symbytes_t:
    tmp = array.copy(p)
    for i in range(kyber_n):
        tmp[i] = compress(tmp[i], 1)
    msg = encode(1, tmp)
    return msg

@contract3(lambda kyber_k, sk: array.length(sk) == kyber_k,
           lambda kyber_k, sk, res: bytes.length(res) == kyber_indcpa_secretkeybytes(kyber_k))
@typechecked
def pack_sk(kyber_k:variant_k, sk:zqpolyvec_t) -> vlbytes_t:
    res = array.create(kyber_polyvecbytes(kyber_k), uint8(0))
    #encode_13(sk mod+ q)    
    for i in range(kyber_k):
        for j in range(kyber_n):
            sk[i][j] = nat_mod.to_int(sk[i][j])

        res[i*kyber_polybytes:(i+1)*kyber_polybytes] = encode(13, sk[i])
    return res

@contract3(lambda kyber_k, packedsk: array.length(packedsk) == kyber_indcpa_secretkeybytes(kyber_k),
           lambda kyber_k, packedsk, res: array.length(res) == kyber_k)
@typechecked
def unpack_sk(kyber_k:variant_k, packedsk:bytes_t) -> zqpolyvec_t:
    res = array.create(kyber_k, array.create(kyber_n, zqelem(0)))
    #decode_13(sk)
    for i in range(kyber_k):
        res[i] = decode(13, packedsk[i*kyber_polybytes:(i+1)*kyber_polybytes])

        for j in range(kyber_n):
            res[i][j] = zqelem(res[i][j])

    return matrix(res)

@contract3(lambda kyber_k, pk, seed: array.length(pk) == kyber_k,
           lambda kyber_k, pk, seed, res: bytes.length(res) == kyber_indcpa_publickeybytes(kyber_k))
@typechecked
def pack_pk(kyber_k:variant_k, pk:zqpolyvec_t, seed:symbytes_t) -> vlbytes_t:
    res = array.create(kyber_indcpa_publickeybytes(kyber_k), uint8(0))
    #(encode_dt(compress_q(t, dt)) || seed)
    for i in range(kyber_k):
        poly_c = array.create(kyber_n, zqelem(0))
        for j in range(kyber_n):
            poly_c[j] = compress(pk[i][j], kyber_dt)
        res[i*352:(i+1)*352] = encode(kyber_dt, poly_c)

    res[kyber_polyveccompressedbytes(kyber_k):kyber_indcpa_publickeybytes(kyber_k)] = seed
    return res

@contract3(lambda kyber_k, packedpk: bytes.length(packedpk) == kyber_indcpa_publickeybytes(kyber_k),
           lambda kyber_k, packedpk, res: True) # array.length(fst(res)) == kyber_k
@typechecked
def unpack_pk(kyber_k:variant_k, packedpk:vlbytes_t) -> tuple2 (zqpolyvec_t, symbytes_t):
    pk = array.create(kyber_k, array.create(kyber_n, zqelem(0)))
    #decompress_q(decode_dt(pk), dt)
    for i in range(kyber_k):
        poly_c = decode(kyber_dt, packedpk[i*352:(i+1)*352])
        for j in range(kyber_n):
            poly_c[j] = decompress(poly_c[j], kyber_dt)
        pk[i] = poly_c

    seed = packedpk[kyber_polyveccompressedbytes(kyber_k):kyber_indcpa_publickeybytes(kyber_k)]
    return (matrix(pk), seed)

@contract3(lambda kyber_k, b, v: array.length(b) == kyber_k,
           lambda kyber_k, b, v, res: bytes.length(res) == kyber_indcpa_bytes(kyber_k))
@typechecked
def pack_ciphertext(kyber_k:variant_k, b:zqpolyvec_t, v:zqpoly_t) -> vlbytes_t:
    res = array.create(kyber_indcpa_bytes(kyber_k), uint8(0))
    #encode_du(compress_q(b, du))
    for i in range(kyber_k):
        poly_c = array.create(kyber_n, zqelem(0))
        for j in range(kyber_n):
            poly_c[j] = compress(b[i][j], kyber_du)
        res[i*352:(i+1)*352] = encode(kyber_du, poly_c)

    #encode_dv(compress_q(v, dv))
    poly_c = array.create(kyber_n, zqelem(0))
    for j in range(kyber_n):
        poly_c[j] = compress(v[j], kyber_dv)
    res[kyber_polyveccompressedbytes(kyber_k):kyber_indcpa_bytes(kyber_k)] = encode(kyber_dv, poly_c)

    return res

@contract3(lambda kyber_k, c: array.length(c) == kyber_indcpa_bytes(kyber_k),
           lambda kyber_k, c, res: True) # array.length(fst(res)) == kyber_k
@typechecked
def unpack_ciphertext(kyber_k:variant_k, c:bytes_t) -> tuple2 (zqpolyvec_t, zqpoly_t):
    u = array.create(kyber_k, array.create(kyber_n, zqelem(0)))
    #decompress_q(decode_du(c), du)
    for i in range(kyber_k):
        poly_c = decode(kyber_du, c[i*352:(i+1)*352])
        for j in range(kyber_n):
            poly_c[j] = decompress(poly_c[j], kyber_du)
        u[i] = poly_c

    #decompress_q(decode_dv(c_v), dv)
    v = decode(kyber_dv, c[kyber_polyveccompressedbytes(kyber_k):kyber_indcpa_bytes(kyber_k)])
    for j in range(kyber_n):
        v[j] = decompress(v[j], kyber_dv)

    return (matrix(u), vector(v))

#Sampling from a binomial distribution
@contract3(lambda kyber_eta, buf: array.length(buf) == kyber_eta * kyber_n // 4,
           lambda kyber_eta, buf, res: True)
@typechecked
def cbd(kyber_eta:variant_eta, buf:bytes_t) -> zqpoly_t:
    beta = bytesToBits(buf)
    res = array.create(kyber_n, zqelem(0))
    for i in range(kyber_n):
        a = nat(0)
        b = nat(0)
        for j in range(kyber_eta):
            a = a + intn.to_int(beta[2 * i * kyber_eta + j])
        for j in range(kyber_eta):
            b = b + intn.to_int(beta[2 * i * kyber_eta + kyber_eta + j])
        res[i] = zqelem(a) - zqelem(b)
    return vector(res)

#cbd(prf(seed, nonce)), prf = shake256
@typechecked
def poly_getnoise(kyber_eta:variant_eta, seed:symbytes_t, nonce:uint8_t) -> zqpoly_t:
    extseed = array.create(kyber_symbytes + 1, uint8(0))
    extseed[0:kyber_symbytes] = seed
    extseed[kyber_symbytes] = nonce
    buf = shake256(kyber_symbytes + 1, extseed, kyber_eta * kyber_n // 4)
    r = cbd(kyber_eta, buf)
    return vector(r)

#Uniform sampling in R q
@typechecked
def shake128_absorb(inputByteLen:size_nat_t,
                    input_b:refine(vlbytes_t, lambda x: array.length(x) == inputByteLen)) -> state_t:
    s = array.create(25, uint64(0))
    return absorb(s, 168, inputByteLen, input_b, uint8(0x1F))

@typechecked
def shake128_squeeze(s:state_t,
                     outputByteLen:size_nat_t) -> refine(vlbytes_t, lambda x: array.length(x) == outputByteLen):
    return squeeze(s, 168, outputByteLen)

#parse(xof(p || a || b)), xof = shake128
@typechecked
def genAij(seed:symbytes_t, a:uint8_t, b:uint8_t) -> zqpoly_t:
    shake128_rate = 168
    res = array.create(kyber_n, zqelem(0))

    extseed = array.create(kyber_symbytes + 2, uint8(0))
    extseed[0:kyber_symbytes] = seed
    extseed[kyber_symbytes] = a
    extseed[kyber_symbytes + 1] = b

    maxnblocks = 4
    nblocks = maxnblocks
    state = shake128_absorb(kyber_symbytes + 2, extseed)
    buf = shake128_squeeze(state, shake128_rate * nblocks)

    i = 0
    j = 0
    while (j < kyber_n):
        d = uint16(buf[i]) | (uint16(buf[i + 1]) << 8)
        d = int(d & uint16(0x1fff))
        if (d < kyber_q):
            res[j] = zqelem(d)
            j = j + 1
        i = i + 2
        if (i > shake128_rate * nblocks - 2):
            nblocks = 1
            buf = shake128_squeeze(state, shake128_rate * nblocks)
            i = 0
    return vector(res)

@contract3(lambda kyber_k, kyber_eta, coins: True,
           lambda kyber_k, kyber_eta, coins, res: True) # array.length(fst(res)) == kyber_indcpa_publickeybytes(kyber_k) and array.length(snd(res)) == kyber_indcpa_secretkeybytes(kyber_k)
@typechecked
def kyber_cpapke_keypair(kyber_k:variant_k, kyber_eta:variant_eta, coins:symbytes_t) -> tuple2 (vlbytes_t, vlbytes_t):
    rhosigma = sha3_512(kyber_symbytes, coins)
    rho = rhosigma[0:kyber_symbytes]
    sigma = rhosigma[kyber_symbytes:(2*kyber_symbytes)]

    n = uint8(0)
    s = matrix(array.create(kyber_k, array.create(kyber_n, zqelem(0))))
    e = matrix(array.create(kyber_k, array.create(kyber_n, zqelem(0))))
    that = matrix(array.create(kyber_k, array.create(kyber_n, zqelem(0))))
    A = array.create(kyber_k, array.create(kyber_k, array.create(kyber_n, zqelem(0))))

    for i in range(kyber_k):
        A[i] = array.create(kyber_k, array.create(kyber_n, zqelem(0)))
        for j in range(kyber_k):
            A[i][j] = array.create(kyber_n, zqelem(0))
    
    for i in range(kyber_k):
        for j in range(kyber_k):
            A[i][j] = vector(genAij(rho, uint8(j), uint8(i)))

    for i in range(kyber_k):
        s[i] = poly_getnoise(kyber_eta, sigma, n)
        n += uint8(1)

    for i in range(kyber_k):
        e[i] = poly_getnoise(kyber_eta, sigma, n)
        n += uint8(1)

    shat = bit_reversed_polyvec(kyber_k, zqpolyvec_ntt(kyber_k, s))

    # that = A * shat
    for i in range(kyber_k):
        for j in range(kyber_k):
            that[i] += A[i][j] * shat[j]

    t = zqpolyvec_invntt(kyber_k, bit_reversed_polyvec(kyber_k, that))
    t = t + e

    sk = pack_sk(kyber_k, shat)
    pk = pack_pk(kyber_k, t, rho)

    return (pk, sk)

@contract3(lambda kyber_k, kyber_eta, m, packedpk, coins: bytes.length(packedpk) == kyber_indcpa_publickeybytes(kyber_k),
           lambda kyber_k, kyber_eta, m, packedpk, coins, res: bytes.length(res) == kyber_indcpa_bytes(kyber_k))
@typechecked
def kyber_cpapke_encrypt(kyber_k:variant_k, kyber_eta:variant_eta, m:symbytes_t, packedpk:vlbytes_t, coins:symbytes_t) -> vlbytes_t:
    n = uint8(0)
    r = matrix(array.create(kyber_k, array.create(kyber_n, zqelem(0))))
    e1 = matrix(array.create(kyber_k, array.create(kyber_n, zqelem(0))))
    uhat = matrix(array.create(kyber_k, array.create(kyber_n, zqelem(0))))
    vhat = vector(array.create(kyber_n, zqelem(0)))
    At = array.create(kyber_k, array.create(kyber_k, array.create(kyber_n, zqelem(0))))

    t, rho = unpack_pk(kyber_k, packedpk)

    for i in range(kyber_k):
        At[i] = array.create(kyber_k, array.create(kyber_n, zqelem(0)))
        for j in range(kyber_k):
            At[i][j] = vector(array.create(kyber_n, zqelem(0)))

    for i in range(kyber_k):
        for j in range(kyber_k):
            At[i][j] = genAij(rho, uint8(i), uint8(j))

    for i in range(kyber_k):
        r[i] = poly_getnoise(kyber_eta, coins, n)
        n += uint8(1)

    for i in range(kyber_k):
        e1[i] = poly_getnoise(kyber_eta, coins, n)
        n += uint8(1)

    e2 = poly_getnoise(kyber_eta, coins, n)

    rhat = bit_reversed_polyvec(kyber_k, zqpolyvec_ntt(kyber_k, r))

    for i in range(kyber_k):
        for j in range(kyber_k):
            uhat[i] += At[i][j] * rhat[j]

    u = zqpolyvec_invntt(kyber_k, bit_reversed_polyvec(kyber_k, uhat))
    u = u + e1

    that = bit_reversed_polyvec(kyber_k, zqpolyvec_ntt(kyber_k, t))

    for i in range(kyber_k):
        vhat += that[i] * rhat[i]

    v = zqpoly_invntt(bit_reversed_poly(vhat))
    v += e2 + msg_to_poly(m)
    c = pack_ciphertext(kyber_k, u, v)

    return c

@contract3(lambda kyber_k, kyber_eta, c, sk: array.length(c) == kyber_indcpa_bytes(kyber_k) and array.length(sk) == kyber_indcpa_secretkeybytes(kyber_k),
           lambda kyber_k, kyber_eta, c, sk, res: True)
@typechecked
def kyber_cpapke_decrypt(kyber_k:variant_k, kyber_eta:variant_eta, c:bytes_t, sk:bytes_t) -> symbytes_t:
    dhat = vector(array.create(kyber_n, zqelem(0)))

    u, v = unpack_ciphertext(kyber_k, c)
    s = unpack_sk(kyber_k, sk)

    uhat = bit_reversed_polyvec(kyber_k, zqpolyvec_ntt(kyber_k, u))

    for i in range(kyber_k):
        dhat += s[i] * uhat[i]

    d = zqpoly_invntt(bit_reversed_poly(dhat))
    d = v - d
    msg = poly_to_msg(d)
    return msg

#KyberKEM
@typechecked
def kyber_publickeybytes(kyber_k:variant_k):
    return kyber_indcpa_publickeybytes(kyber_k)

@typechecked
def kyber_secretkeybytes(kyber_k:variant_k):
    return (kyber_indcpa_secretkeybytes(kyber_k) + kyber_indcpa_publickeybytes(kyber_k) + 2 * kyber_symbytes)

@typechecked
def kyber_ciphertextbytes(kyber_k:variant_k):
    return kyber_indcpa_bytes(kyber_k)

@contract3(lambda kyber_k, kyber_eta, keypaircoins, coins: True,
           lambda kyber_k, kyber_eta, keypaircoins, coins, res: True) #array.length(fst(res)) == kyber_publickeybytes(kyber_k) and array.length(snd(res)) == kyber_secretkeybytes(kyber_k)
@typechecked
def crypto_kem_keypair(kyber_k:variant_k, kyber_eta:variant_eta, keypaircoins:symbytes_t, coins:symbytes_t) -> tuple2 (vlbytes_t, vlbytes_t):
    sk = array.create(kyber_secretkeybytes(kyber_k), uint8(0))
    pk, sk1 = kyber_cpapke_keypair(kyber_k, kyber_eta, keypaircoins)
    sk[0:kyber_indcpa_secretkeybytes(kyber_k)] = sk1
    sk[kyber_indcpa_secretkeybytes(kyber_k):(kyber_indcpa_secretkeybytes(kyber_k) + kyber_indcpa_publickeybytes(kyber_k))] = pk
    sk[(kyber_indcpa_secretkeybytes(kyber_k) + kyber_indcpa_publickeybytes(kyber_k)):(kyber_secretkeybytes(kyber_k) - kyber_symbytes)] = sha3_256(kyber_publickeybytes(kyber_k), pk)
    sk[(kyber_secretkeybytes(kyber_k) - kyber_symbytes):kyber_secretkeybytes(kyber_k)] = coins
    return (pk, sk)

@contract3(lambda kyber_k, kyber_eta, pk, msgcoins: bytes.length(pk) == kyber_publickeybytes(kyber_k),
           lambda kyber_k, kyber_eta, pk, msgcoins, res: True) #array.length(fst(res)) == kyber_ciphertextbytes(kyber_k)
@typechecked
def crypto_kem_enc(kyber_k:variant_k, kyber_eta:variant_eta, pk:vlbytes_t, msgcoins:symbytes_t) -> tuple2 (vlbytes_t, symbytes_t):
    buf = array.create(2 * kyber_symbytes, uint8(0))

    buf[0:kyber_symbytes] = sha3_256(kyber_symbytes, msgcoins)
    buf[kyber_symbytes:(2 * kyber_symbytes)] = sha3_256(kyber_publickeybytes(kyber_k), pk)

    kr = sha3_512(2 * kyber_symbytes, buf)
    ct = kyber_cpapke_encrypt(kyber_k, kyber_eta, buf[0:kyber_symbytes], pk, kr[kyber_symbytes:(2*kyber_symbytes)])
    kr[kyber_symbytes:(2*kyber_symbytes)] = sha3_256(kyber_ciphertextbytes(kyber_k), ct)
    ss = sha3_256(2*kyber_symbytes, kr)
    return (ct, ss)

@contract3(lambda kyber_k, kyber_eta, ct, sk: bytes.length(ct) == kyber_ciphertextbytes(kyber_k) and array.length(sk) == kyber_secretkeybytes(kyber_k),
           lambda kyber_k, kyber_eta, ct, sk, res: True)
@typechecked
def crypto_kem_dec(kyber_k:variant_k, kyber_eta:variant_eta, ct:vlbytes_t, sk:bytes_t(kyber_secretkeybytes)) -> symbytes_t:
    buf = array.create(2 * kyber_symbytes, uint8(0))
    pk = sk[kyber_indcpa_secretkeybytes(kyber_k):(kyber_indcpa_secretkeybytes(kyber_k) + kyber_indcpa_publickeybytes(kyber_k))]
    sk1 = sk[0:kyber_indcpa_secretkeybytes(kyber_k)]
    buf[0:kyber_symbytes] = kyber_cpapke_decrypt(kyber_k, kyber_eta, ct, sk1)
    buf[kyber_symbytes:(2 * kyber_symbytes)] = sk[(kyber_indcpa_secretkeybytes(kyber_k) + kyber_indcpa_publickeybytes(kyber_k)):(kyber_secretkeybytes(kyber_k) - kyber_symbytes)]
    kr = sha3_512(2 * kyber_symbytes, buf)
    cmp1 = kyber_cpapke_encrypt(kyber_k, kyber_eta, buf[0:kyber_symbytes], pk, kr[kyber_symbytes:(2 * kyber_symbytes)])
    kr[kyber_symbytes:(2 * kyber_symbytes)] = sha3_256(kyber_ciphertextbytes(kyber_k), ct)
    if (cmp1 == ct):
        kr[0:kyber_symbytes] = kr[0:kyber_symbytes]
    else:
        kr[0:kyber_symbytes] = sk[(kyber_secretkeybytes(kyber_k) - kyber_symbytes):kyber_secretkeybytes(kyber_k)]
    ss = sha3_256(2 * kyber_symbytes, kr)
    return ss
