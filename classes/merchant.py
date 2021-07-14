import socket, ssl, pickle

from ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, \
    get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign
from const import merchant_id, payer_id, payer_payment_request_port
from utils import generate_nonce


class Merchant:
    def __init__(self, name='merchant'):
        self.cert_pem, private_key_byte = generate_selfsigned_cert(subject_name=name)
        self.public_key = get_public_key_object_from_cert_file(self.cert_pem)
        self.private_key = get_private_key_object_from_private_byte(private_key_byte)
        self.payment_req_nonce = None

    def create_payment_request(self, price):
        nonce = generate_nonce()
        bill = merchant_id + "||" + str(price) + "||" + str(nonce)
        bill = bill.encode('utf-8')
        signed_bill = sign(self.private_key, bill)
        self.payment_req_nonce = nonce
        return bill, signed_bill, self.cert_pem

    # if return False we have to restart this step of protocol
    def handle_ack_payment_request(self, request):
        message, signed_message, cert_payer = request
        pk_payer = get_public_key_object_from_cert_file(cert_payer)
        p_id, nonce = message.decode().split("||")
        if payer_id != p_id:
            return False
        if int(nonce) != int(self.payment_req_nonce) + 1:
            return False
        if not validate_sign(pk_payer, signed_message, message):
            return False
        return True

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


if __name__ == '__main__':
    m = Merchant()
    payment = m.create_payment_request(245000)
    if m.send_payment_to_payer(payment):
        print(f"Payment request succeeded.")
