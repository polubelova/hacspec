#To run these specs in Python you need to install Python >= 3.6
PYTHON?=python3.6

all: test

test:
	$(PYTHON) speclib_test.py
	$(PYTHON) poly1305_test.py
	$(PYTHON) chacha20_test.py
	$(PYTHON) aead_chacha20poly1305_test.py
	$(PYTHON) sha2_test.py
	$(PYTHON) keccak_test.py
	$(PYTHON) blake2_test.py
	$(PYTHON) argon2i_test.py
	$(PYTHON) curve25519_test.py
	$(PYTHON) ed25519_test.py
	$(PYTHON) vrf_test.py
	$(PYTHON) p256_test.py
	$(PYTHON) curve448_test.py
	$(PYTHON) rsapss_test.py
	$(PYTHON) kyber_test.py
	$(PYTHON) wots_test.py # this takes a while
	$(PYTHON) frodo_test.py

check-specs:
	$(PYTHON) ../spec-checker/spec-checker.py blake2.py
	$(PYTHON) ../spec-checker/spec-checker.py chacha20.py
	$(PYTHON) ../spec-checker/spec-checker.py poly1305.py
	$(PYTHON) ../spec-checker/spec-checker.py aead_chacha20poly1305.py
	$(PYTHON) ../spec-checker/spec-checker.py sha2.py
	$(PYTHON) ../spec-checker/spec-checker.py keccak.py
	$(PYTHON) ../spec-checker/spec-checker.py curve25519.py
	$(PYTHON) ../spec-checker/spec-checker.py curve448.py
	$(PYTHON) ../spec-checker/spec-checker.py wots.py
	$(PYTHON) ../spec-checker/spec-checker.py argon2i.py
	$(PYTHON) ../spec-checker/spec-checker.py ed25519.py
	$(PYTHON) ../spec-checker/spec-checker.py vrf.py
	$(PYTHON) ../spec-checker/spec-checker.py rsapss.py
	$(PYTHON) ../spec-checker/spec-checker.py kyber.py
	$(PYTHON) ../spec-checker/spec-checker.py frodo.py
