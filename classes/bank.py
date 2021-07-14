import os

from ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, \
    get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign
from const import merchant_id, payer_id, bank_id, certs_path
from utils import generate_nonce


class Bank:
    def __init__(self, name='Bank'):
        self.key_path = certs_path + "bank.key"
        self.cert_path = certs_path + "bank.cert"
        if os.path.exists(self.key_path) and os.path.exists(self.cert_path):
            with open(self.key_path, "rb") as f:
                private_key_byte = f.read()
            with open(self.key_path, "rb") as f:
                self.cert_pem = f.read()

        else:
            self.cert_pem, private_key_byte = generate_selfsigned_cert(subject_name=name)

            with open(self.key_path, "w+b") as f:
                f.write(private_key_byte)
            with open(self.cert_path, "w+b") as f:
                f.write(self.cert_pem)

        self.private_key = get_private_key_object_from_private_byte(private_key_byte)
        self.merchant_pk = None
        self.payment_preparation_nonce2 = None

    # p1.2
    def ack_payment_preparation(self, message):
        valid_message = True
        payment, signed_message, cert_payer = message
        # we assume bank validate IDs in its database (like below)

        p_id = payment[0]
        m_id = payment[1]
        if not validate_sign(get_public_key_object_from_cert_file(cert_payer), signed_message, payment):
            valid_message = False
        elif p_id != payer_id or m_id != merchant_id:
            valid_message = False
        if not valid_message:
            return False, None
        nonce1 = int(payment[-1])
        self.payment_preparation_nonce2 = generate_nonce()
        verification = bank_id + "||" + str(nonce1 + 1) + "||" + self.payment_preparation_nonce2
        return True, verification.encode('utf-8'), sign(self.private_key, verification), self.cert_pem

    # p1.4
    def handle_ack_ack_payment_preparation(self, message):
        is_valid = False
        verification_ack, signed_verification, cert_payer = message
        if not validate_sign(get_public_key_object_from_cert_file(cert_payer), signed_verification, verification_ack):
            is_valid = False
        if not is_valid:
            return False, None
        return True, 'we move to the next stage #p4'


if __name__ == "__main__":
    bank = Bank()
