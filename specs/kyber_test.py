from speclib import *
from kyber import kyber_cpapke_keypair, kyber_cpapke_encrypt, kyber_cpapke_decrypt
from sys import exit

def test(msg, keypaircoins, encryptcoins, num):
    sk, pk, rho = kyber_cpapke_keypair(keypaircoins)
    u, v = kyber_cpapke_encrypt(msg, pk, rho, encryptcoins)
    msg1 = kyber_cpapke_decrypt(u, v, sk)

    if (msg == msg1):
        print("Kyber Test "+str(num)+" successful!")
    else:
        print("Kyber Test failed!")
        print("Computed msg: " + str(msg1))
        print("Expected msg: " + str(msg))
        exit(1)

def main(x: int) -> None:
    keypaircoins = array.create(32, uint8(0))
    for i in range(32):
        keypaircoins[i] = uint8(i)

    encryptcoins = array.create(32, uint8(0))
    for i in range(32):
        encryptcoins[i] = uint8(32 + i)

    msg = array.create(32, uint8(0))
    for i in range(32):
        msg[i] = uint8(i + 1)

    test(msg, keypaircoins, encryptcoins, 0)

if __name__ == "__main__":
    main(0)
