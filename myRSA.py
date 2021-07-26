from random import randint as randint
def isPrime(num, test_count):
    if test_count >= num:
        test_count = num - 1
    for x in range(test_count):
        val = randint(2, num - 1)
        if RSA_encrypt(val, num - 1, num) - 1:
            return False
    return True

def generatePrimeNum(n):
    while True:
        tmp = randint(2**(n-1), 2**n -1)
        if isPrime(tmp, 5000):
            return tmp

def gcd(a, b):
    if a == 0:
        return b
    return gcd(b % a, a)

def invMulti(a, n):
    r1, r2 = n, a
    t1, t2 = 0, 1
    while(r2):
        q = r1 // r2
        r = r1 - q * r2
        r1, r2 = r2, r
        t = t1 - q * t2
        t1, t2 = t2, t
    return t1 if t1 >= 0 else (t1 + n)

def RSA_encrypt(a, m, n):
    b = 1
    while b <= m:
        b <<= 1
    b >>= 1
    p = 1
    while b:
        p = p * p % n
        if (b & m) != 0:
            p = p * a % n
        b >>= 1
    return p

def generate_RSA_key():
    p = generatePrimeNum(512)
    q = generatePrimeNum(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = randint(2, phi - 1)
    while gcd(e, phi) - 1:
        e = randint(e, phi - 1)
    d = invMulti(e, phi)
    return p, q, n, e, d