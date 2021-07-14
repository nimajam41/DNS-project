import os
import random
from ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, \
    get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign
from const import merchant_id, payer_id, bank_id, certs_path
from utils import generate_nonce
from datetime import datetime, timedelta


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
        self.resp_price_nonce = None
        self.transaction_seq_number = 1
        public_wallet_payer_path = certs_path + "wallet_payer.cert"
        with open(public_wallet_payer_path, "rb") as f:
            wallet_cert = f.read()
        self.public_wallet_payer = get_public_key_byte_from_cert_file(wallet_cert)

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

    # p3.4
    def handle_ack_ack_payment_preparation(self, message):
        is_valid = False
        verification_ack, signed_verification, cert_payer = message
        if not validate_sign(get_public_key_object_from_cert_file(cert_payer), signed_verification, verification_ack):
            is_valid = False
        if not is_valid:
            return False, None
        return True, 'we move to the next stage #p4'

    # p4.1
    def request_price(self, price_fiat=1000):
        self.resp_price_nonce = generate_nonce()
        return (str(price_fiat) + "||" + str(self.resp_price_nonce)).encode("utf-8")

    # p4.3
    # get price and request transaction into block_chain
    def request_transaction(self, resp_price):
        is_valid = True
        msg, signed_msg, cert_exchange = resp_price
        crypto_amount, nonce = msg.decode().split("||")
        if int(nonce) != 1 + self.resp_price_nonce:
            is_valid = False
        elif validate_sign(get_public_key_object_from_cert_file(cert_exchange), signed_msg, msg):
            is_valid = False
        if not is_valid:
            return False, None
        transaction = crypto_amount + "||" + str(self.transaction_seq_number)
        return True, self.public_wallet_payer, get_public_key_byte_from_cert_file(self.cert_pem), transaction.encode(
            "utf-8"), sign(self.private_key, self.public_wallet_payer + "||" + transaction)

    def handle_transaction_resp(self, msg):
        is_valid = True
        msg, signed_msg, cert_blockchain = msg
        status, seq_number = msg.decode().split("||")
        # status handle transaction between payer and merchant inside bank
        if seq_number != self.transaction_seq_number:
            is_valid = False
        elif not validate_sign(get_public_key_object_from_cert_file(cert_blockchain), signed_msg, msg):
            is_valid = False
        if not is_valid:
            return False, None
        self.transaction_seq_number += 1
        return True, "moving to 5th stage"


    # p5.2
    def response_payment_confirmation(self, message):
        is_valid = True
        req, signed_req, cert_merchant = message
        m_id, nonce = req.decode().split("||")
        if m_id != merchant_id:
            is_valid = False
        elif not validate_sign(get_public_key_object_from_cert_file(cert_merchant), signed_req, req):
            is_valid = False
        if not is_valid:
            return False, None
        res = bank_id + "||" + str(int(nonce) + 1) + "||" + str(random.randint(0, 100000))
        return True, res.encode('utf-8'), sign(self.private_key, res.encode('utf-8')), self.cert_pem


if __name__ == "__main__":
    bank = Bank()
