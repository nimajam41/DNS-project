from datetime import datetime, timedelta
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def generate_selfsigned_cert(hostname='root', ip_addresses=None, key=None, subject_name=None):
    subject_name = subject_name if subject_name is not None else hostname
    if key is None:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    ])

    # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.
    alt_names = [x509.DNSName(hostname)]

    if ip_addresses:
        for addr in ip_addresses:
            alt_names.append(x509.DNSName(addr))
            alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))

    san = x509.SubjectAlternativeName(alt_names)

    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.utcnow()
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name)
    ])
    cert = (
        x509.CertificateBuilder()
            .subject_name(subject_name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1000)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=10 * 365))
            .add_extension(basic_contraints, False)
            .add_extension(san, False)
            .sign(key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, key_pem


# return public_key file like to save
def get_public_key_byte_from_cert_file(cert: x509.Certificate):
    return x509.load_pem_x509_certificate(cert, backend=default_backend()).public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)


# return public_key object to work with
def get_public_key_object_from_cert_file(cert: x509.Certificate):
    return x509.load_pem_x509_certificate(cert, backend=default_backend()).public_key()

def get_public_key_object_from_public_byte(key):
    return serialization.load_pem_public_key(key, backend=default_backend())

# return private_key object to work with
def get_private_key_object_from_private_byte(key_pem):
    return serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())


# need public_key object as input, message should be in byte format
def encrypt(public_key, message):
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


# need private_key object as input
def decrypt(private_key, encypted_message):
    original_message = private_key.decrypt(
        encypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message


# sign byte like message with private_key object
def sign(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256()
    )


# public_key : object, message: byte, signed_message: byte
def validate_sign(public_key, signed_message, message):
    try:
        public_key.verify(
            signed_message,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


if __name__ == '__main__':
    cert, private_bytes = generate_selfsigned_cert('Merchant')
    public_key = get_public_key_object_from_cert_file(cert)
    print(get_public_key_byte_from_cert_file(cert))
    private_key = get_private_key_object_from_private_byte(private_bytes)
    print(public_key)
    print(private_key)
    x = encrypt(public_key, message=b'salam')
    print(x)
    print(decrypt(private_key, x))
    xx = sign(private_key, b'in ro sign kon')
    print(validate_sign(public_key, xx, b'in ro sign kon'))
