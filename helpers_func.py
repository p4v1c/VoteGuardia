from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


def generate_aes_key():
    """
    Generate a random 32-byte AES key.
    Returns bytes
    """
    return os.urandom(32)

def encrypt_with_aes(aes_key, plaintext):
    """
    Encrypt plaintext (str) with AES-CBC.
    Returns (iv, ciphertext).
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))

    encryptor = cipher.encryptor()
    block_size = algorithms.AES.block_size // 8

    # Calc du padding

    padded_plaintext = plaintext.encode('utf-8')
    padding_needed = block_size - (len(padded_plaintext) % block_size)
    padded_plaintext += bytes([padding_needed]) * padding_needed

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv + ciphertext  # prepend IV to the ciphertext

def decrypt_with_aes(aes_key, iv_ciphertext):
    """
    Decrypt data (IV + ciphertext) with AES-CBC.
    Returns original plaintext (str).
    """
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    padding_value = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_value]
    return plaintext.decode('utf-8')

def encrypt_aes_key_with_rsa(aes_key, public_key):
    """
    Encrypt the AES key (bytes) with the server's public RSA key.
    Returns the encrypted AES key (bytes).
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
    Generate an HMAC of the encrypted vote using the same AES key (or a separate HMAC key).
    """
    h = hmac.HMAC(aes_key, hashes.SHA256())
    h.update(encrypted_vote)
    return h.finalize()

def verify_hmac(aes_key, encrypted_vote, hmac_value):
    """
    Verify the HMAC to ensure vote data hasn't been tampered with.
    Raises an exception if verification fails.
    """
    h = hmac.HMAC(aes_key, hashes.SHA256())
    h.update(encrypted_vote)
    h.verify(hmac_value)



def rsa_init():
    """
    Helper func to init RSA primitives for the server
    In real world application key managment would be more secure
    """
PRIVATE_KEY_FILE = "server_private_key.pem"
PUBLIC_KEY_FILE = "server_public_key.pem"
if not os.path.exists(PRIVATE_KEY_FILE):
    # On génère + serialize le jeu de clées si ces dernières n'existent pas
    # Elles sont lues dans le cas ivnerse
    server_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

 
    server_public_key = server_private_key.public_key()


    with open(PRIVATE_KEY_FILE, "wb") as private_key_file:
        private_key_file.write(
            server_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    with open(PUBLIC_KEY_FILE, "wb") as public_key_file:
        public_key_file.write(
            server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
else:
    with open(PRIVATE_KEY_FILE, "rb") as private_key_file:
        server_private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None
        )
    with open(PUBLIC_KEY_FILE, "rb") as public_key_file:
        server_public_key = serialization.load_pem_public_key(
            public_key_file.read()
        )
server_public_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)