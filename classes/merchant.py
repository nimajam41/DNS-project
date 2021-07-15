import os
import socket, ssl, pickle

from ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, \
    get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign
from const import merchant_id, payer_id, payer_payment_request_port, certs_path, bank_id, bank_get_confirmation_port, \
    PRICE
from utils import generate_nonce


class Merchant:
    def __init__(self, name='merchant'):
        self.key_path = certs_path + "merchant.key"
        self.cert_path = certs_path + "merchant.cert"

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
        self.payment_req_nonce = None
        self.payment_confirmation_nonce = None

    # p2.1
    def create_payment_request(self, price):
        nonce = generate_nonce()
        bill = merchant_id + "||" + str(price) + "||" + str(nonce)
        bill = bill.encode('utf-8')
        signed_bill = sign(self.private_key, bill)
        self.payment_req_nonce = nonce
        return bill, signed_bill, self.cert_pem

    # if return False we have to restart this step of protocol
    # p2.3
    def handle_ack_payment_request(self, request):
        message, signed_message, cert_payer = request
        pk_payer = get_public_key_object_from_cert_file(cert_payer)
        p_id, nonce = message.decode().split("||")
        if payer_id != p_id:
            return False, None
        if int(nonce) != int(self.payment_req_nonce) + 1:
            return False, None
        if not validate_sign(pk_payer, signed_message, message):
            return False, None
        return True, "we move to the next phase #p3"

    def send_payment_to_payer(self, payment_request):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            ssl_sock = ssl.wrap_socket(sock)
            ssl_sock.connect(('localhost', payer_payment_request_port))
            ssl_sock.sendall(pickle.dumps(payment_request))
            res = ssl_sock.recv(4096)
            ack = pickle.loads(res)
            if not ack == "Invalid Request":
                return self.handle_ack_payment_request(ack)
            else:
                print("Invalid Payment Request")
                return False

    # p5.1
    def request_payment_confirmation(self):
        self.payment_confirmation_nonce = generate_nonce()
        req = (merchant_id + "||" + str(self.payment_confirmation_nonce)).encode('utf-8')
        signed_part = sign(self.private_key, req)
        return req, signed_part, self.cert_pem

    # p5.3
    def handle_response_payment_confirmation(self, message):
        is_valid = True
        print(message)
        res, signed_res, cert_bank = message
        b_id, received_nonce, amount = res.decode().split("||")
        if b_id != bank_id:
            is_valid = False
        elif int(received_nonce) != 1 + self.payment_confirmation_nonce:
            is_valid = False
        elif not validate_sign(get_public_key_object_from_cert_file(cert_bank), signed_res, res):
            is_valid = False
        if not is_valid:
            return False
        return 'Current balance fetched'

    def send_confirmation_request_to_bank(self, payment_confirmation):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            ssl_sock = ssl.wrap_socket(sock)
            ssl_sock.connect(('localhost', bank_get_confirmation_port))
            ssl_sock.sendall(pickle.dumps(payment_confirmation))
            res = ssl_sock.recv(4096)
            ack = pickle.loads(res)
            if not ack == "Invalid Request":
                return self.handle_response_payment_confirmation(ack)
            else:
                print("Invalid Confirmation Request")
                return False

if __name__ == '__main__':
    m = Merchant()
    payment = m.create_payment_request(PRICE)
    if m.send_payment_to_payer(payment):
        print(f"Payment request succeeded.")

    payment_confirmation = m.request_payment_confirmation()
    result = m.send_confirmation_request_to_bank(payment_confirmation)
    if result:
        print(result)
