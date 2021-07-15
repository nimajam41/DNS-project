import os
from threading import Thread

from ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, \
    get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign
from const import payer_id, merchant_id, bank_id, certs_path, exchange_get_price_port
from utils import generate_nonce

import socket, ssl, pickle


class CryptoExchange:
    def __init__(self, name='CryptoExchange'):
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

    # p4.2
    def resp_price_to_bank(self, msg):
        amount, nonce = msg.decode().split("||")
        crypto_amount = self.price(amount_source=float(amount))
        resp = str(crypto_amount) + "||" + str(int(nonce) + 1)
        return resp.encode('utf-8'), sign(self.private_key, resp.encode('utf-8')), self.cert_pem

    def run_price_request_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            ssl_sock = ssl.wrap_socket(sock, keyfile=self.key_path,
                                       certfile=self.cert_path, server_side=True,
                                       do_handshake_on_connect=True)
            ssl_sock.bind(('localhost', exchange_get_price_port))
            ssl_sock.listen()
            while True:
                conn, addr = ssl_sock.accept()
                with conn:
                    print(f'Connected by {addr} to receive price request')
                    data = conn.recv(4096)
                    price_request = pickle.loads(data)
                    ack = self.resp_price_to_bank(price_request)
                    if ack:
                        conn.sendall(pickle.dumps(ack))

                    else:
                        conn.sendall(pickle.dumps("Invalid Request"))


if __name__ == "__main__":
    exchange = CryptoExchange()
    Thread(target=exchange.run_price_request_server).start()