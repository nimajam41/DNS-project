import os

from ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, \
    get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign
from const import payer_id, merchant_id, bank_id, blockchain_port, certs_path, PRICE
from utils import generate_nonce

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
            print(self.payer_key_path)
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
        self.payment_price = None

    # we assume we have bank's pk
    # p1.1
    def create_delegation(self, range, count, timestamp, bank_public_key_file):
        policy = str(range) + "||" + str(count) + "||" + str(timestamp) + "||" + str(self.last_seq_number)
        policy = policy.encode('utf-8')
        message_to_sign = (bank_public_key_file.decode() + "||" + policy.decode()).encode('utf-8')
        self.last_seq_number = int(self.last_seq_number)
        return (
            bank_public_key_file, self.public_key_wallet_byte, policy, sign(self.private_key_wallet, message_to_sign))

    #p1.3
    def handle_delegation_ack(self, message):
        seq_number, signed_message, pub_cer_blockchain = message
        pub_block_chain = get_public_key_object_from_cert_file(pub_cer_blockchain)
        if int(seq_number.decode()) != self.last_seq_number:
            return False
        elif validate_sign(pub_block_chain, signed_message, seq_number):
            self.last_seq_number += 1
            return True

        # inja age false bud bayad replay koni create_delegation va inaro dg
        return False

    # we assume price value is always correct (user will check it by its knowledge)
    # p2.2
    def handle_payment_request(self, payment_request):
        bill, signed_bill, merchant_pk_certificate = payment_request
        self.payment_price = int(bill.decode().split("||")[1])
        merchant_pk = get_public_key_object_from_cert_file(merchant_pk_certificate)
        self.merchant_pk = get_public_key_byte_from_cert_file(merchant_pk_certificate)
        nonce = int(bill.decode().split("||")[-1])
        if self.payment_price != PRICE:
            return False, None
        elif validate_sign(merchant_pk, signed_bill, bill):
            return True, self.create_ack_payment_request(nonce + 1)
        return False, None

    # اینجا ورودیش در اصل nonce+1 فانکشن بالاست
    # p2.2
    def create_ack_payment_request(self, nonce):
        message = (payer_id + "||" + str(nonce)).encode('utf-8')
        return message, sign(self.private_key, message), self.cert_pem

    # p3.1
    def create_payment_preparation(self):
        nonce1 = str(generate_nonce())
        payment = payer_id + "||" + merchant_id + "||" + get_public_key_byte_from_cert_file(
            self.cert_pem_wallet) + "||" + self.merchant_pk.decode() + "||" + self.payment_price + "||" + nonce1
        message = payment.encode('utf-8'), sign(self.private_key, payment.encode('utf-8')), self.cert_pem
        self.payment_preparation_nonce1 = nonce1
        return message
    # p3.4
    def ack_ack_payment_preparation(self, message):
        is_valid = True
        verification_ack, signed_verification, cert_bank = message
        b_id, nonce1, nonce2 = verification_ack
        if b_id != bank_id:
            is_valid = False
        if int(nonce1) - 1 != int(self.payment_preparation_nonce1):
            is_valid = False
        if not validate_sign(get_public_key_object_from_cert_file(cert_bank), signed_verification, verification_ack):
            is_valid = False
        if not is_valid:
            return False, None

        verify_part = payer_id + "||" + str(int(nonce2) + 1)
        return True, verify_part.encode('uft-8'), sign(self.private_key, verify_part.encode('utf-8')), self.cert_pem


if __name__ == '__main__':
    p = Payer()
    with open(certs_path + "bank.cert", "rb") as f:
        pk_bank = f.read()
    delegation = p.create_delegation(200, 2, 18526220589.27749, pk_bank)
    print(delegation)

    # 2.2
    x = p.handle_payment_request((
                                 b'88ec7410-a926-467e-a254-dbede767d4a9||245000||21965283331697416175132629525820752178433382050109120638807612341534241881357',
                                 b'}!\x93\x8c\xf0\x0e\xab\xdb\x10\xb8!y\xd8\x95W\xb7\x92X\xec\xa0\xa0?\x8cX\xd3t\x80k\x96n\xf6;\xad\xed\x1b\x03\xd1\x04\xb8G\x00\x9e\xc23\xc7_u\'\xfc\xc3@\xfb.\xec\xe6\\\x16\xf4y\xe4\xd9\xe8\xddT\xa12\t\xab\'s\xaf\xdfw\x93\x0cO\xf8\x9aH\x00\x9e\xcf\x93\xb8dc\x8bS\r\x18\x17\x0b\r\xcc,d\x076\xfbA{\x87\x7f\xb5\xe6\xde*m\xda\x06\xcf\xf0\xf6\xed\x0e\xdf\xe8\\\xab\xb6-\x92\x95Yrbg\x0bzO~O\xad\x82^z=\xdd\x91e/\xd6p+\x0bi\xd9p\x13\x9b\xcf\x0c\xc15\'\x1a\xd8\xderZi\xf0\x07\xb0\xe9\xaa\xea-\xb5\xf0\xecX\xfb\xc2\x19\x12*/m\xf5\xe8\x10\x8b\xa4\x89@=\xe5W(\x97\x93t\xf5\xae\xb2p\xc4w^ \xd7\xc8\xe0\x80\x97C\xbc\xa1\x01k:d,\\\xd9\xc5\x8a\xaa.\x89\xb8\x0c\xd6\x127V\x87/,7\x88\x90\xa8\x80v\x1de?\xa3j\x1e\\\x95vAGP\xb2(\x1b\xeb"\x97\xa6\xe9',
                                 b'-----BEGIN CERTIFICATE-----\nMIICvzCCAaegAwIBAgICA+gwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwEcm9v\ndDAeFw0yMTA3MTQxNzAyMzZaFw0zMTA3MTIxNzAyMzZaMBAxDjAMBgNVBAMMBXBh\neWVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn7hlNgcpeHnyMbjN\ne+0h+wT+uzPucZcGMkuIS7fwYrjfURlYDSoDdA9Wle5MG2TDSduNOtQCwMOcYsvb\n4Bq68LmqqutcQGk6u6AN4CcYvpmDbAsesWq79d1X5G4jfvdZ8Dps0jeiq9dGn0OW\nqebOuQIRiRFExINT9FVsoUyReo45wp3PPrvKyQDrb6BbbiQeS3ZjnAXRaucHUAK5\nPkKmykUAka7YhJiHS80/QdOSS+QPTRI7qfPYl6416ZZ8N431KzdRP0HCHRklF/aR\nBjJ32reRPcdFcW9LplAwsPxfhACr59IN30eN4hYVrRU3oh5h7csUx9AaKyovQQTL\n9RqQhwIDAQABoyQwIjAPBgNVHRMECDAGAQH/AgEAMA8GA1UdEQQIMAaCBHJvb3Qw\nDQYJKoZIhvcNAQELBQADggEBAEsjQoVYiD7a7EHNE1Yg7v35Lh4EkaKskzmeTSDU\nis353GIFLtMtcP0M4KeyENrnnjDmXHTPLHpB0XB7CFBo6OotYAtO1oct7N4nVEJw\nZZvGAUWRu+dppj5Y7eLOpfo3fRGWZh79R6dzKBVGV5wiO2QQ6LjmgsSv7F4ja9lA\ne3vunw1Hs/syDgj8FiMzjSD2KSJrmtW1zMTN+/0NFrB/nhmqvnK0EDeLNXmn+8MK\nEfAprsPs0dMuWrP5t138sFuuYutTYsg3vdVKOBjZ9ArK/DIxijvWtgZsEL1Ex0Dh\niUM5T4YuYu7RGINpYchwg9su5Kd4mhyBAiNhl1SJx758u14=\n-----END CERTIFICATE-----\n')
                                 )
    print(x)

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
