import os

from ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, \
    get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign
from const import payer_id, merchant_id
from utils import generate_nonce

from const import payer_id, blockchain_port, certs_path
import socket, ssl, pickle

class Payer:
    def __init__(self, name='payer', last_seq_number=1):
        self.payer_key_path = certs_path + "payer.key"
        self.payer_cert_path = certs_path + "payer.cert"
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

        self.public_key = get_public_key_object_from_cert_file(self.cert_pem)
        self.private_key = get_private_key_object_from_private_byte(private_key_byte)

        self.wallet_payer_key_path = certs_path + "wallet_payer.key"
        self.wallet_payer_cert_path = certs_path + "wallet_payer.cert"
        if os.path.exists(self.wallet_payer_key_path) and os.path.exists(self.wallet_payer_cert_path):
            with open(self.wallet_payer_key_path, "rb") as f:
                private_key_file_wallet = f.read()
            with open(self.wallet_payer_cert_path, "rb") as f:
                self.cert_pem_wallet = f.read()

        else:
            self.cert_pem_wallet, private_key_file_wallet = generate_selfsigned_cert(subject_name='wallet_' + name)

            with open(self.wallet_payer_key_path, "wb") as f:
                f.write(private_key_file_wallet)
            with open(self.wallet_payer_cert_path, "wb") as f:
                f.write(self.cert_pem_wallet)

        self.public_key_wallet_byte = get_public_key_byte_from_cert_file(self.cert_pem_wallet)
        self.public_key_wallet = get_public_key_object_from_cert_file(self.cert_pem_wallet)
        self.private_key_wallet = get_private_key_object_from_private_byte(private_key_file_wallet)
        self.last_seq_number = last_seq_number
        self.merchant_pk = None
        self.payment_preparation_nonce1 = None
        self.payment_preparation_nonce2 = None
        self.payment_price = None

    # we assume we have bank's pk
    def create_delegation(self, range, count, timestamp, bank_public_key_file):
        policy = str(range) + "||" + str(count) + "||" + str(timestamp) + "||" + str(self.last_seq_number)
        policy = policy.encode('utf-8')
        message_to_sign = (bank_public_key_file.decode() + "||" + policy.decode()).encode('utf-8')
        self.last_seq_number = int(self.last_seq_number)
        return (
            bank_public_key_file, self.public_key_wallet_byte, policy, sign(self.private_key_wallet, message_to_sign))

    def handle_delegation_ack(self, message):
        seq_number, signed_message, pub_cer_blockchain = message
        pub_block_chain = get_public_key_object_from_cert_file(pub_cer_blockchain)
        if validate_sign(pub_block_chain, signed_message, seq_number):
            self.last_seq_number += 1
            return True

        # inja age false bud bayad replay koni create_delegation va inaro dg
        return False

    # we assume price value is always correct (user will check it by its knowledge)
    def handle_payment_request(self, payment_request):
        bill, signed_bill, merchant_pk_certificate = payment_request
        self.payment_price = bill.decode().split("||")
        merchant_pk = get_public_key_object_from_cert_file(merchant_pk_certificate)
        self.merchant_pk = get_public_key_byte_from_cert_file(merchant_pk_certificate)
        nonce = int(bill.decode().split("||")[-1])
        if validate_sign(merchant_pk, signed_bill, bill):
            return True, self.create_ack_payment_request(nonce + 1)
        return False, None

    # اینجا ورودیش در اصل nonce+1 فانکشن بالاست
    def create_ack_payment_request(self, nonce):
        message = (payer_id + "||" + str(nonce)).encode('utf-8')
        return message, sign(self.private_key, message), self.cert_pem

    def create_payment_preparation(self):
        nonce1 = str(generate_nonce())
        payment = payer_id + "||" + merchant_id + "||" + get_public_key_byte_from_cert_file(
            self.cert_pem_wallet) + "||" + self.merchant_pk.decode() + "||" + self.payment_price + "||" + nonce1
        message = payment.encode('utf-8'), sign(self.private_key, payment.encode('utf-8')), self.cert_pem
        self.payment_preparation_nonce1 = nonce1
        return message


if __name__ == '__main__':
    p = Payer()
    with open(certs_path + "bank.cert", "rb") as f:
        pk_bank = f.read()
    delegation = p.create_delegation(200, 2, 18526220589.27749, pk_bank)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        s = ssl.wrap_socket(sock)
        s.connect(('localhost', blockchain_port))
        s.sendall(pickle.dumps(delegation))
        res = s.recv(4096)
        ack = pickle.loads(res)
        if not ack == "Invalid Request":
            print(ack[2].decode())
        else:
            print("Invalid Delegation Request")
