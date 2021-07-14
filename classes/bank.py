import os
import pickle
import socket
import ssl
from threading import Thread

from ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, \
    get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign
from const import merchant_id, payer_id, bank_id, certs_path, bank_send_preparation_port
from utils import generate_nonce


class Bank:
    def __init__(self, name='Bank'):
        self.key_path = certs_path + "bank.key"
        self.cert_path = certs_path + "bank.cert"
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

        self.private_key = get_private_key_object_from_private_byte(private_key_byte)
        self.merchant_pk = None
        self.payment_preparation_nonce2 = None

    # p1.2
    def ack_payment_preparation(self, message):
        valid_message = True
        payment, signed_message, cert_payer = message
        # we assume bank validate IDs in its database (like below)
        if not validate_sign(get_public_key_object_from_cert_file(cert_payer), signed_message, payment):
            return False

        payment = payment.decode().split("||")
        p_id = payment[0]
        m_id = payment[1]
        if p_id != payer_id or m_id != merchant_id:
            valid_message = False
        if not valid_message:
            return False
        nonce1 = int(payment[-1])
        self.payment_preparation_nonce2 = generate_nonce()
        verification = bank_id + "||" + str(nonce1 + 1) + "||" + str(self.payment_preparation_nonce2)
        return verification.encode('utf-8'), sign(self.private_key, verification.encode('utf-8')), self.cert_pem

    # p1.4
    def handle_ack_ack_payment_preparation(self, message):
        is_valid = True
        verification_ack, signed_verification, cert_payer = message
        if not validate_sign(get_public_key_object_from_cert_file(cert_payer), signed_verification, verification_ack):
            is_valid = False
        if not is_valid:
            return False
        return 'we move to the next stage #p4'

    def run_payment_preparation_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            ssl_sock = ssl.wrap_socket(sock, keyfile=self.key_path,
                                       certfile=self.cert_path, server_side=True,
                                       do_handshake_on_connect=True)
            ssl_sock.bind(('localhost', bank_send_preparation_port))
            ssl_sock.listen()
            while True:
                conn, addr = ssl_sock.accept()
                with conn:
                    print(f'Connected by {addr} to receive payment preparation')
                    data = conn.recv(4096)
                    payment_preparation = pickle.loads(data)
                    ack = self.ack_payment_preparation(payment_preparation)
                    if ack:
                        conn.sendall(pickle.dumps(ack))
                        data = conn.recv(4096)
                        ack_data = pickle.loads(data)
                        ack_ack = self.handle_ack_ack_payment_preparation(ack_data)
                        print(ack_ack)
                    else:
                        conn.sendall(pickle.dumps("Invalid Request"))


if __name__ == "__main__":
    bank = Bank()
    Thread(target=bank.run_payment_preparation_server).start()
