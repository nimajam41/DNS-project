import os

from ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, \
    get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign
from const import payer_id, merchant_id, bank_id, blockchain_port, certs_path
from utils import generate_nonce

import socket, ssl, pickle


class CryptoExchange:
    def __init__(self, name):
        self.key_path = certs_path + "exchange.key"
        self.cert_path = certs_path + "exchange.cert"

        if os.path.exists(self.key_path) and os.path.exists(self.cert_path):
            with open(self.key_path, "rb") as f:
                private_key_byte = f.read()
            with open(self.cert_path, "rb") as f:
                self.cert_pem = f.read()

        else:
            self.cert_pem, private_key_byte = generate_selfsigned_cert(subject_name=name)
            with open(self.key_path, "w+b") as f:
                f.write(private_key_byte)
            with open(self.cert_path, "w+b") as f:
                f.write(self.cert_pem)

        self.public_key = get_public_key_object_from_cert_file(self.cert_pem)
        self.private_key = get_private_key_object_from_private_byte(private_key_byte)
        self.crypto_to_rial = {
            'BTC': 1000,
        }

    # اینجا مثلا میگیم انقدر ریال چند بیت‌کوین میشه.
    # فرض کردیم کلا بیت‌کوین داریم میفروشیم دیگه
    def price(self, amount_source, dest_ex='BTC'):
        return amount_source / self.crypto_to_rial[dest_ex]

    def aync_exchange(self):
        pass

    # p4.2
    def resp_price_to_bank(self, msg):
        amount, nonce = msg.decode().split("||")
        crypto_amount = self.price(amount_source=amount)
        resp = str(crypto_amount) + "||" + str(int(nonce) + 1)
        return resp.encode('utf-8'), sign(self.private_key, resp.encode('utf-8')), self.cert_pem
