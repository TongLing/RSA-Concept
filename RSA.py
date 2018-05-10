import random
import math

'''
Description: RSA Encryption and Decryption Function
             Private Exponent Attack Function based on n and e.

Author:      Ling Tong

Finished at: April 9, 2018

'''


def modinv(e, phi):
    '''
    :param phi: euler function of n (i.e. phi = (p-1)(q-1) )
    :param e: a random e which meets ed = 1 (mod phi)
    :return: d, the modular inverse value of
    '''
    for x in range(1, phi):
        if (e * x) % phi == 1:
            return x
    return None


def isqrt(n):
    '''
    Calculates the integer square root
    for arbitrary large nonnegative integers
    '''
    if n < 0:
        raise ValueError('square root not defined for negative numbers')

    if n == 0:
        return 0
    a, b = divmod(bitlength(n), 2)
    x = 2 ** (a + b)
    while True:
        y = (x + n // x) // 2
        if y >= x:
            return x
        x = y


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in xrange(3, int(num ** 0.5) + 2, 2):
        if num % n == 0:
            return False
    return True


def generate_keypair(p, q, e=-1):
    '''
    Description: given p, q (probably along with e), generate public key (e,n) and private key(d, n)
    :return:     public key (e, n) and private key (d, n)
    '''
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    # n = pq
    n = p * q
    # Phi is the totient of n
    phi = (p - 1) * (q - 1)
    # Choose an integer e such that e and phi(n) are coprime
    if e == -1:
        e = random.randrange(1, phi)
    print "phi =", phi
    print "random seleting a valid value e ... e =", e
    # Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # Use Extended Euclid's Algorithm to generate the pr

    # ivate key
    d = modinv(e, phi)
    print "n =", n
    print "d =", d
    # Return public and private keypair
    # Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))


def encrypt(publicKey, plaintext):
    '''
    given public key and text, return ciphertext
    '''
    # Unpack the key into it's components
    key, n = publicKey
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    ciphertext = [(ord(char) ** key) % n for char in plaintext]
    # Return the array of bytes
    return ciphertext


def decrypt(privateKey, ciphertext):
    '''
    given private key and cipher, return decrypted text
    '''
    # Unpack the key into its components
    key, n = privateKey
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr((char ** key) % n) for char in ciphertext]
    # Return the array of bytes as a string
    return ''.join(plain)


def rational_to_contfrac(x, y):
    '''
    Converts a rational x/y fraction into
    a list of partial quotients [a0, ..., an]
    '''
    a = x // y
    pquotients = [a]
    while a * y != x:
        x, y = y, x - a * y
        a = x // y
        pquotients.append(a)
    return pquotients


# TODO: efficient method that calculates convergents on-the-go, without doing partial quotients first
def convergents_from_contfrac(frac):
    '''
    computes the list of convergents
    using the list of partial quotients
    '''
    convs = [];
    for i in range(len(frac)):
        convs.append(contfrac_to_rational(frac[0:i]))
    return convs


def contfrac_to_rational(frac):
    '''Converts a finite continued fraction [a0, ..., an]
     to an x/y rational.
     '''
    if len(frac) == 0:
        return (0, 1)
    num = frac[-1]
    denom = 1
    for _ in range(-2, -len(frac) - 1, -1):
        num, denom = frac[_] * num + denom, num
    return (num, denom)


def is_perfect_square(n):
    '''
    If n is a perfect square it returns sqrt(n),
    otherwise returns -1
    '''
    h = n & 0xF  # last hexadecimal "digit"
    if h > 9:
        return -1  # return immediately in 6 cases out of 16.

    # Take advantage of Boolean short-circuit evaluation
    if (h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8):
        # take square root if you must
        t = isqrt(n)
        if t * t == n:
            return t
        else:
            return -1
    return -1


def bitlength(x):
    '''
    Calculates the bitlength of x
    '''
    assert x >= 0
    n = 0
    while x > 0:
        n = n + 1
        x = x >> 1
    return n


def hack_RSA(e, n):
    '''
    Finds d knowing (e,n)
    applying the Wiener continued fraction attack
    '''
    frac = rational_to_contfrac(e, n)
    convergents = convergents_from_contfrac(frac)
    for (k, d) in convergents:
        # check if d is actually the key
        if k != 0 and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = n - phi + 1
            # check if the equation x ^ 2 - s * x + n = 0
            # has integer roots
            discr = s * s - 4 * n
            if (discr >= 0):
                t = is_perfect_square(discr)
                if t != -1 and (s + t) % 2 == 0:
                    print("Hack successful!")
                    return d
                else:
                    continue
    print "Hack failed"


def test_hack_RSA():
    '''
    Testing Wiener Attack given the based e and n.
    '''
    print("===== Trying to hack private key based on Wiener Attack algorithm ======")

    e = 3728438759195168737135992109727249348803612435894359189081738936348226606690336984297449194984522245267347608647851637838095872369329569971857522894319893342321565064748765439590130905828618062110655958711360104101926567503619653408915623418784429679330189884729041367661885435565586952318599099463080887219162354874117983707707854892379461221207015463083472995141690891986170606756925711854474324916913314927750891337011838020040295424415142917065939663073173249929035030071510843219620490640863993468878684803620906049125234829708750801749587906700784584868164495039453453030247421811968896558706354352374798351579
    n = 13944220401877938113014934848099117271555842144465711135230872813021395268695304462884287334296659283504546204155028953304304152419500276351517026203090560312682332100557949888340674488347457083400825956841368247339132128545661778946404948547066296060177763630405864758766614366952316600616993369171973988711601072880358006049128862543088069228671596572559102238313290682720666719883296361722526485195136936001869087770636745643885209795529748130091587883621035733051140981054393173745532828558933056050658667881198651606339538768702135427015143742705493428714835468242036488501979845083076916758773475058112957196487
    hacked_d = hack_RSA(e, n)
    print "the private key (d) =", hacked_d


def RSA_process(p, q, message):
    '''
    a test with message encryption and decryption
    message: plaintext
    '''
    print "==== generating key pairs, achieve encryption and decryption... ==="
    print "p =", p, ", q =", q, "."
    print "Generating your public/private keypairs now..."
    public, private = generate_keypair(p, q)
    print "Your public key is", public, ", your private key is", private
    print "The original message is:", message
    encrypted_msg = encrypt(public, message)

    print "the encrypted message is: "
    print ''.join(map(lambda x: str(x), encrypted_msg))

    print "Decrypting message with private key", public, "..."

    print "the Decrypted message is:"
    print decrypt(private, encrypted_msg)

    print "======RSA encryption and decryption ends============="


if __name__ == "__main__":
    RSA_process(p=103, q=97, message="hello world")
    # test_hack_RSA()
