from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

#
# ==============
# VULNERABLE HELPERS
# ==============
# 1. RSA Key: Hardcoded small primes (p = 13, q = 17), easily factorable (n = 221).
# 2. AES Key: Short, static key; using ECB mode (reveals data patterns).
# 3. HMAC: Uses MD5 instead of a modern hash like SHA256.


# 1. Extremely weak, short, and hardcoded AES key (16 bytes for AES-128).
STATIC_AES_KEY = b'0123456789ABCDEF'  # 16-byte key: easily guessable

def generate_aes_key():
    """
    Returns a SHORT, STATIC AES key (vulnerable).
    """
    return STATIC_AES_KEY

def encrypt_with_aes(aes_key, plaintext):
    """
    Encrypt plaintext with AES in ECB mode (vulnerable).
    
    - ECB mode leaks patterns (identical blocks -> identical ciphertext).
    - Using a static key as well.
    """
    from Crypto.Cipher import AES

    cipher = AES.new(aes_key, AES.MODE_ECB)
    block_size = AES.block_size

    padded_plaintext = plaintext.encode('utf-8')
    padding_needed = block_size - (len(padded_plaintext) % block_size)
    padded_plaintext += bytes([padding_needed]) * padding_needed

    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext 

def decrypt_with_aes(aes_key, ciphertext):
    """
    Decrypt data with AES in ECB mode (vulnerable).
    """
    from Crypto.Cipher import AES

    cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted_padded = cipher.decrypt(ciphertext)

    # Remove padding
    padding_value = decrypted_padded[-1]
    decrypted = decrypted_padded[:-padding_value]
    return decrypted.decode('utf-8')

def encrypt_aes_key_with_rsa(aes_key, public_key):
    """
    Encrypt the AES key (bytes) using RSA-OAEP.
    Even though OAEP is relatively modern, the RSA key itself is trivially factorable.
    """
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key):
    """
    Decrypt the AES key with the server's private RSA key.
    However, that RSA key is intentionally weak (small primes).
    """
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

def generate_hmac(aes_key, encrypted_vote):
    """
    Generate an HMAC using MD5 (vulnerable).
    
    MD5 is broken and not collision-resistant.
    """
    from cryptography.hazmat.primitives.hashes import MD5

    h = hmac.HMAC(aes_key, MD5())
    h.update(encrypted_vote)
    return h.finalize()

def verify_hmac(aes_key, encrypted_vote, hmac_value):
    """
    Verify HMAC with MD5. Subject to collision attacks.
    """
    from cryptography.hazmat.primitives.hashes import MD5

    h = hmac.HMAC(aes_key, MD5())
    h.update(encrypted_vote)
    h.verify(hmac_value)



PRIVATE_KEY_FILE = "server_private_key.pem"
PUBLIC_KEY_FILE = "server_public_key.pem"

# We'll store them in global variables for demonstration
server_private_key = None
server_public_key = None
server_public_pem = None
n_public = None

def rsa_init():
    """
    Initializes RSA with a known broken primes
    """
    global server_private_key, server_public_key, server_public_pem, n_public

    # Build private key object from known primes, exponent, etc.
    p = 20423438101489158688419303567277343858734758547418158024698288475832952556286241362315755217906372987360487170945062468605428809604025093949866146482515539
    q = 6703903965361517118576511528025622717463828698514771456694902115718276634989944955753407851598489976727952425488221391817052769267904281935379659980013749
    n = p * q
    e = 65537          
    d = 44845741106690268103514149249424607519594508246909250227414936129701447302226114727179316965627790007729213560128014568833093489136852691041346166421569620534290510082390858265871547245719419662328573431637651551301140798550078735596651062433867422527058531366469274576735492716859066557272178885046932242705           
    dmp1 = d % (p - 1) 
    dmq1 = d % (q - 1) 

    # q^-1 mod p -> inverse of q mod p
    iqmp = pow(q, -1, p)

    private_numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n)
    )

    server_private_key = private_numbers.private_key(default_backend())
    server_public_key = server_private_key.public_key()

    # Serialize to PEM (so the rest of the app can still read them if needed)
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(
            server_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(
            server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    server_public_pem = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    n_public = n
