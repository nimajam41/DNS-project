from classes.ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, \
    get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign
from classes.const import cert_file, payer_id, merchant_id
from classes.utils import generate_nonce


class Bank:
    def __init__(self, name):
        self.cert_pem, private_key_byte = generate_selfsigned_cert(subject_name=name)
        self.private_key = get_private_key_object_from_private_byte(private_key_byte)
        self.merchant_pk = None
        self.payment_preparation_nonce1 = None
        self.payment_preparation_nonce2 = None

    def ack_payment_preparation(self, message):
        pass


