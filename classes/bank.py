import os

from ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, \
    get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign
from const import payer_id, merchant_id, certs_path
from utils import generate_nonce


class Bank:
    def __init__(self, name='Bank'):
        self.payer_key_path = certs_path + "bank.key"
        self.payer_cert_path = certs_path + "bank.cert"
        if os.path.exists(self.payer_key_path) and os.path.exists(self.payer_cert_path):
            with open(self.payer_key_path, "rb") as f:
                private_key_byte = f.read()
            with open(self.payer_cert_path, "rb") as f:
                self.cert_pem = f.read()

        else:
            self.cert_pem, private_key_byte = generate_selfsigned_cert(subject_name=name)

            with open(self.payer_key_path, "w+b") as f:
                f.write(private_key_byte)
            with open(self.payer_cert_path, "w+b") as f:
                f.write(self.cert_pem)

        self.cert_pem, private_key_byte = generate_selfsigned_cert(subject_name=name)
        self.private_key = get_private_key_object_from_private_byte(private_key_byte)
        self.merchant_pk = None
        self.payment_preparation_nonce1 = None
        self.payment_preparation_nonce2 = None

    def ack_payment_preparation(self, message):
        pass

if __name__ == "__main__":
    bank = Bank()
