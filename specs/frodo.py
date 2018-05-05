from speclib import *
from keccak import absorb, squeeze, state_permute

# Parameters for "FrodoKEM-640"
crypto_secretkeybytes = 19872
crypro_publickeybytes = 9616
crypto_bytes = 16
crypto_ciphertextbytes = 9736

params_n = 640
params_nbar = 8
params_logq = 15
params_q = 2 ** params_logq
params_extracted_bits = 2
params_stripe_step = 8
params_parallel = 4
bytes_seed_a = 16
bytes_mu = (params_extracted_bits * params_nbar * params_nbar) // 8

cdf_table_len = 12
cdf_table = array([4727, 13584, 20864, 26113, 29434, 31278, 32176, 32560, 32704, 32751, 32764, 32767])

def cshake128_frodo(inputByteLen:nat,
                    input_b:refine(vlbytes_t, lambda x: array.length(x) == inputByteLen),
                    cstm:uint16_t,
                    outputByteLen:nat) -> refine(vlbytes_t, lambda x: array.length(x) == outputByteLen):

    delimitedSuffix = uint8(0x04)
    rateInBytes = 168

    s1 = array.create(8, uint8(0))
    s1[0] = uint8(0x01)
    s1[1] = uint8(0xa8)
    s1[2] = uint8(0x01)
    s1[3] = uint8(0x00)
    s1[4] = uint8(0x01)
    s1[5] = uint8(16)
    s1[6] = uint8(cstm)
    s1[7] = uint8(cstm >> 8)

    s = array.create(25, uint64(0))
    s[0] = vlbytes.to_uint64_le(s1)
    s = state_permute(s)

    s = absorb(s, rateInBytes, inputByteLen, input_b, delimitedSuffix)
    output = squeeze(s, rateInBytes, outputByteLen)
    return output

def vlbytes_to_uint16 (aLen:nat, a:vlarray_t(uint8)) -> vlarray_t(uint16):
    resLen = aLen // 2
    res = array.create(resLen, uint16(0))
    for i in range(resLen):
        res[i] = vlbytes.to_uint16_le(a[(i * 2):(i * 2 + 2)])
    return res

def frodo_sample_n(n:nat, seedLen:nat, seed:bytes_t, ctr:uint16_t) -> vlarray_t(uint16):
    res = array.create(n, uint16(0))
    r = cshake128_frodo(seedLen, seed, ctr, n * 2)
    r = vlbytes_to_uint16(n * 2, r)

    for i in range(n):
        sample = uint16(0)
        prnd = r[i] >> 1
        sign = r[i] & uint16(0x01)

        for z in range(cdf_table_len - 1):
            sample = sample + ((uint16(cdf_table[z]) - prnd) >> 15)
        res[i] = ((-sign) ^ sample) + sign
    return res

def frodo_gen_matrix(n:nat, seedLen:nat, seed:bytes_t) -> vlarray_t(uint16):
    res = array.create(n * n, uint16(0))
    for i in range(n):
        res_i = cshake128_frodo(seedLen, seed, uint16(256 + i), n * 2)
        res_i = vlbytes_to_uint16(n * 2, res_i)
        res[(i*n):(i*n + n)] = res_i
    return res

#res = a * s + e
def frodo_mul_add_as_plus_e(a:vlarray_t(uint16), s:vlarray_t(uint16), e:vlarray_t(uint16)) -> vlarray_t(uint16):
    #res = array.create(params_n * params_nbar, uint16(0))
    res = array.copy(e)
    for i in range(params_n):
        for k in range(params_nbar):
            tmp = uint16(0)
            for j in range(params_n):
                tmp = tmp + a[i * params_n + j] * s[k * params_n + j]
            res[i * params_nbar + k] = res[i * params_nbar + k] + tmp
    return res

#res = s * a + e
def frodo_mul_add_sa_plus_e(a:vlarray_t(uint16), s:vlarray_t(uint16), e:vlarray_t(uint16)) -> vlarray_t(uint16):
    #res = array.create(params_nbar * params_n, uint16(0))
    res = array.copy(e)
    for i in range(params_n):
        for k in range(params_nbar):
            tmp = uint16(0)
            for j in range(params_n):
                tmp = tmp + a[j * params_n + i] * s[k * params_n + j]
            res[k * params_n + i] = res[k * params_n + i] + tmp
    return res

#res = s * b + e
def frodo_mul_add_sb_plus_e(b:vlarray_t(uint16), s:vlarray_t(uint16), e:vlarray_t(uint16)) -> vlarray_t(uint16):
    res = array.create(params_nbar * params_nbar, uint16(0))
    mod = (uint16(1) << params_logq) - uint16(1)
    for k in range(params_nbar):
        for i in range(params_nbar):
            res[k*params_nbar+i] = e[k*params_nbar +i]
            for j in range(params_n):
                res[k*params_nbar+i] = res[k*params_nbar+i] + s[k*params_n+j] * b[j*params_nbar+i]
            res[k*params_nbar+i] = res[k*params_nbar+i] & mod
    return res

#res = b * s
def frodo_mul_bs(b:vlarray_t(uint16), s:vlarray_t(uint16)) -> vlarray_t(uint16):
    res = array.create(params_nbar * params_nbar, uint16(0))
    mod = (uint16(1) << params_logq) - uint16(1)
    for i in range(params_nbar):
        for j in range(params_nbar):
            res[i*params_nbar+j] = uint16(0)
            for k in range(params_n):
                res[i*params_nbar+j] = res[i*params_nbar+j] + b[i*params_n+k] * s[j*params_n+k]
            res[i*params_nbar+j] = res[i*params_nbar+j] & mod
    return res

#res = a + b
def frodo_add(a:vlarray_t(uint16), b:vlarray_t(uint16)) -> vlarray_t(uint16):
    res = array.create(params_nbar * params_nbar, uint16(0))
    mod = (uint16(1) << params_logq) - uint16(1)
    for i in range(params_nbar * params_nbar):
        res[i] = (a[i] + b[i]) & mod
    return res

#res = a - b
def frodo_sub(a:vlarray_t(uint16), b:vlarray_t(uint16)) -> vlarray_t(uint16):
    res = array.create(params_nbar * params_nbar, uint16(0))
    mod = (uint16(1) << params_logq) - uint16(1)
    for i in range(params_nbar * params_nbar):
        res[i] = (a[i] - b[i]) & mod
    return res

#res = res % mod
def frodo_mod(a:vlarray_t(uint16)) -> vlarray_t(uint16):
    resLen = array.length(a)
    res = array.create(resLen, uint16(0))
    mod = (uint16(1) << params_logq) - uint16(1)
    for i in range(resLen):
        res[i] = a[i] & mod
    return res

def min(a:nat, b:nat):
    if a < b:
        return a
    else:
        return b

def frodo_pack(aLen:nat, a:vlarray_t(uint16), lsb:nat, resLen:nat) -> bytes_t:
    res = array.create(resLen, uint8(0))
    i = 0
    j = 0
    w = uint16(0)
    bits = 0

    while ((i < resLen) and (j < aLen or (j == aLen and bits > 0))):
        b = 0
        while (b < 8):
            nbits = min(8 - b, bits)
            mask = (uint16(1) << nbits) - uint16(1)
            t = uint8((w >> (bits - nbits)) & mask)
            res[i] = res[i] + (t << (8 - b - nbits))
            b = b + nbits
            bits = bits - nbits

            if (bits == 0):
                if (j < aLen):
                    w = a[j]
                    bits = lsb
                    j = j + 1
                else:
                    break
            if (b == 8):
                i = i + 1
    return res

def frodo_unpack(aLen:nat, a:bytes_t, lsb:nat, resLen:nat) -> vlarray_t(uint16):
    res = array.create(resLen, uint16(0))
    i = 0
    j = 0
    w = uint16(0)
    bits = 0

    while (i < resLen and ((j < aLen) or (j == aLen and bits > 0))):
        b = 0
        while (b < lsb):
            nbits = min(lsb - b, bits)
            mask = (uint16(1) << nbits) - uint16(1)
            t = (w >> (bits - nbits)) & mask
            res[i] = res[i] + (t << (lsb - b - nbits))
            b = b + nbits
            bits = bits - nbits

            if (bits == 0):
                if (j < aLen):
                    w = uint16(a[j])
                    bits = 8
                    j = j + 1
                else:
                    break
            if (b == lsb):
                i = i + 1
    return res

def frodo_key_encode(a:bytes_t) -> vlarray_t(uint16):
    res = array.create(params_nbar * params_nbar, uint16(0))
    npieces_word = 8
    nwords = (params_nbar * params_nbar) // 8
    mask = (uint64(1) << params_extracted_bits) - uint64(1)
    k = 0

    for i in range(nwords):
        temp = uint64(0)
        for j in range(params_extracted_bits):
            temp = temp + (uint64(a[i*params_extracted_bits+j]) << (8*j))
        for j in range(npieces_word):
            res[k] = uint16((temp & mask) << (params_logq - params_extracted_bits))
            temp = temp >> params_extracted_bits
            k = k + 1
    return res

def frodo_key_decode(a:vlarray_t(uint16)) -> bytes_t:
    res = array.create(params_nbar * params_nbar, uint8(0))
    index = 0
    npieces_word = 8
    nwords = (params_nbar * params_nbar) // 8
    maskex = (uint16(1) << params_extracted_bits) - uint16(1)
    maskq = (uint16(1) << params_logq) - uint16(1)

    for i in range(nwords):
        templong = uint64(0)
        for j in range(npieces_word):
            temp = ((a[index] & maskq) + (uint16(1) << (params_logq - params_extracted_bits - 1))) >> (params_logq - params_extracted_bits)
            templong = templong + (uint64(temp & maskex) << (params_extracted_bits * j))
            index = index + 1

        for j in range(params_extracted_bits):
            res[i*params_extracted_bits+j] = uint8(templong >> (8*j))
    return res

def crypto_kem_keypair(coins:bytes_t(2*crypto_bytes+bytes_seed_a)) -> (bytes_t(crypro_publickeybytes), bytes_t(crypto_secretkeybytes)):
    pk = array.create(crypro_publickeybytes, uint8(0))
    sk = array.create(crypto_secretkeybytes, uint8(0))

    s = coins[0:crypto_bytes]
    seed_e = coins[crypto_bytes:(2*crypto_bytes)]
    z = coins[(2*crypto_bytes):(2*crypto_bytes+bytes_seed_a)]

    seed_a = cshake128_frodo(bytes_seed_a, z, uint16(0), bytes_seed_a)

    s_matrix = frodo_sample_n(params_n * params_nbar, crypto_bytes, seed_e, uint16(1))
    e_matrix = frodo_sample_n(params_n * params_nbar, crypto_bytes, seed_e, uint16(2))
    a_matrix = frodo_gen_matrix(params_n, bytes_seed_a, seed_a)

    b_matrix = frodo_mul_add_as_plus_e(a_matrix, s_matrix, e_matrix)
    b = frodo_pack(params_n * params_nbar, b_matrix, params_logq, crypro_publickeybytes - bytes_seed_a)

    pk[0:bytes_seed_a] = seed_a
    pk[bytes_seed_a:crypro_publickeybytes] = b

    sk[0:crypto_bytes] = s
    sk[crypto_bytes:(crypto_bytes + crypro_publickeybytes)] = pk
    sk[(crypto_bytes + crypro_publickeybytes):crypto_secretkeybytes] = s_matrix
    return (pk, sk)

def crypto_kem_enc(coins:bytes_t, pk:bytes_t(crypro_publickeybytes)) -> (bytes_t(crypto_ciphertextbytes), bytes_t(crypto_bytes)):
    seed_a = pk[0:bytes_seed_a]
    b = pk[bytes_seed_a:crypro_publickeybytes]

    temp = array.create(crypro_publickeybytes + bytes_mu, uint8(0))
    temp[0:crypro_publickeybytes] = pk
    temp[crypro_publickeybytes:(crypro_publickeybytes + bytes_mu)] = coins
    g = cshake128_frodo(crypro_publickeybytes + bytes_mu, temp, uint16(3), 3 * crypto_bytes)
    seed_e = g[0:crypto_bytes]
    k = g[crypto_bytes:(2 * crypto_bytes)]
    d = g[(2*crypto_bytes):(3*crypto_bytes)]

    sp_matrix = frodo_sample_n(params_nbar * params_n, crypto_bytes, seed_e, uint16(4))
    ep_matrix = frodo_sample_n(params_nbar * params_n, crypto_bytes, seed_e, uint16(5))
    a_matrix = frodo_gen_matrix(params_n, bytes_seed_a, seed_a)
    bp_matrix = frodo_mul_add_sa_plus_e(a_matrix, sp_matrix, ep_matrix)
    c1Len = (params_logq * params_n * params_nbar) // 8
    c1 = frodo_pack(params_nbar * params_n, bp_matrix, params_logq, c1Len)

    epp_matrix = frodo_sample_n(params_nbar * params_nbar, crypto_bytes, seed_e, uint16(6))
    b_matrix = frodo_unpack(crypro_publickeybytes-bytes_seed_a, b, params_logq, params_n * params_nbar)
    v_matrix = frodo_mul_add_sb_plus_e(b_matrix, sp_matrix, epp_matrix)

    mu_encode = frodo_key_encode(coins)
    c_matrix = frodo_add(v_matrix, mu_encode)
    c2Len = (params_logq * params_nbar * params_nbar) // 8
    c2 = frodo_pack(params_nbar * params_nbar, c_matrix, params_logq, c2Len)

    #ss_init = c1 || c2 || k || d
    ssiLen = c1Len+c2Len+2*crypto_bytes
    ss_init = array.create(ssiLen, uint8(0))
    ss_init[0:c1Len] = c1
    ss_init[c1Len:(c1Len+c2Len)] = c2
    ss_init[(c1Len+c2Len):(ssiLen-crypto_bytes)] = k
    ss_init[(ssiLen-crypto_bytes):ssiLen] = d
    ss = cshake128_frodo(ssiLen, ss_init, uint16(7), crypto_bytes)

    #ct = c1 || c2 || d
    ct = array.create(crypto_ciphertextbytes, uint8(0))
    ct[0:c1Len] = c1
    ct[c1Len:(c1Len+c2Len)] = c2
    ct[(c1Len+c2Len):crypto_ciphertextbytes] = d
    return (ct, ss)

def crypto_kem_dec(ct:bytes_t(crypto_ciphertextbytes), sk:bytes_t(crypto_secretkeybytes)) -> bytes_t(crypto_bytes):
    #parse ct
    c1Len = (params_logq * params_n * params_nbar) // 8
    c2Len = (params_logq * params_nbar * params_nbar) // 8
    c1 = ct[0:c1Len]
    c2 = ct[c1Len:(c1Len+c2Len)]
    d = ct[(c1Len+c2Len):crypto_ciphertextbytes]

    #parse sk
    s = sk[0:crypto_bytes]
    pk = sk[crypto_bytes:(crypto_bytes+crypro_publickeybytes)]
    seed_a = pk[0:bytes_seed_a]
    b = pk[bytes_seed_a:crypro_publickeybytes]
    s_matrix = sk[(crypto_bytes + crypro_publickeybytes):crypto_secretkeybytes]


    bp_matrix = frodo_unpack(c1Len, c1, params_logq, params_n * params_nbar)
    c_matrix = frodo_unpack(c2Len, c2, params_logq, params_nbar * params_nbar)
    m_matrix = frodo_mul_bs(bp_matrix, s_matrix)
    m_matrix = frodo_sub(c_matrix, m_matrix)
    mu_decode = frodo_key_decode(m_matrix)

    temp = array.create(crypro_publickeybytes + bytes_mu, uint8(0))
    temp[0:crypro_publickeybytes] = pk
    temp[crypro_publickeybytes:(crypro_publickeybytes+bytes_mu)] = mu_decode
    g = cshake128_frodo(crypro_publickeybytes + bytes_mu, temp, uint16(3), 3 * crypto_bytes)
    seed_ep = g[0:crypto_bytes]
    kp = g[crypto_bytes:(2 * crypto_bytes)]
    dp = g[(2*crypto_bytes):(3*crypto_bytes)]

    sp_matrix = frodo_sample_n(params_nbar * params_n, crypto_bytes, seed_ep, uint16(4))
    ep_matrix = frodo_sample_n(params_nbar * params_n, crypto_bytes, seed_ep, uint16(5))
    a_matrix = frodo_gen_matrix(params_n, bytes_seed_a, seed_a)
    bpp_matrix = frodo_mul_add_sa_plus_e(a_matrix, sp_matrix, ep_matrix)
    bpp_matrix = frodo_mod(bpp_matrix)

    epp_matrix = frodo_sample_n(params_nbar * params_nbar, crypto_bytes, seed_ep, uint16(6))
    b_matrix = frodo_unpack(crypro_publickeybytes-bytes_seed_a, b, params_logq, params_n * params_nbar)
    v_matrix = frodo_mul_add_sb_plus_e(b_matrix, sp_matrix, epp_matrix)

    mu_encode = frodo_key_encode(mu_decode)
    cp_matrix = frodo_add(v_matrix, mu_encode)

    #ss_init = c1 || c2 || (kp or s) || d
    ssiLen = c1Len+c2Len+2*crypto_bytes
    ss_init = array.create(ssiLen, uint8(0))
    ss_init[0:c1Len] = c1
    ss_init[c1Len:(c1Len+c2Len)] = c2
    ss_init[(ssiLen-crypto_bytes):ssiLen] = d

    if (d == dp and bp_matrix == bpp_matrix and c_matrix == cp_matrix):
        ss_init[(c1Len+c2Len):(ssiLen-crypto_bytes)] = kp
    else:
        ss_init[(c1Len+c2Len):(ssiLen-crypto_bytes)] = s

    ss = cshake128_frodo(ssiLen, ss_init, uint16(7), crypto_bytes)
    return ss
