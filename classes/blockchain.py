import os
from threading import Thread

from ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, \
    get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign, get_public_key_object_from_public_byte
from collections import defaultdict
from const import certs_path, blockchain_send_delegation_port
from datetime import datetime
import socket, ssl, pickle

class BlockChain:
    def __init__(self, name='BlockChain'):
        self.blockchain_key_path = certs_path + "blockchain.key"
        self.blockchain_cert_path = certs_path + "blockchain.cert"
        if os.path.exists(self.blockchain_key_path) and os.path.exists(self.blockchain_cert_path):
            with open(self.blockchain_key_path, "rb") as f:
                private_key_byte = f.read()
            with open(self.blockchain_cert_path, "rb") as f:
                self.cert_pem = f.read()

        else:
            self.cert_pem, private_key_byte = generate_selfsigned_cert(subject_name=name)

            with open(self.blockchain_key_path, "w+b") as f:
                f.write(private_key_byte)
            with open(self.blockchain_cert_path, "w+b") as f:
                f.write(self.cert_pem)
        self.public_key = get_public_key_object_from_cert_file(self.cert_pem)
        self.private_key = get_private_key_object_from_private_byte(private_key_byte)
        self.blocks = defaultdict(dict)

    def add_new_block(self, bank_public, wallet_public, policy):
        key = (bank_public, wallet_public)
        if key in self.blocks and float(self.blocks[key]['timestamp']) > datetime.now().timestamp():
            return False
        range, count, timestamp, seq_number = policy.split('||')

        # possibly replay attack (we are waiting for last_seq_number + 1)
        if key in self.blocks and self.blocks[key]['seq_number'] != seq_number - 1:
            return False
        self.blocks[key] = {
            'range': range,
            'count': count,
            'timestamp': timestamp,
            'seq_number': int(seq_number)
        }
        return True

    def handle_delegation(self, delegation_message):
        delegation_request_valid = True
        pk_file_bank, pk_wallet_user, policy, signed_message = delegation_message
        wallet_pk_object = get_public_key_object_from_public_byte(pk_wallet_user)

        if not validate_sign(wallet_pk_object, signed_message,
                               (pk_file_bank.decode() + "||" + policy.decode()).encode('utf-8')):
            delegation_request_valid = False
        elif len(policy.decode().split('||')) != 4:
            delegation_request_valid = False
        if delegation_request_valid:
            seq_number = policy.decode().split('||')[-1]
            new_block = self.add_new_block(pk_file_bank.decode(), pk_wallet_user.decode(), policy.decode())
            if new_block:
                ack_del = self.ack_delegation(seq_number.encode('utf-8'))
                return ack_del
        else:
            return None

    def ack_delegation(self, seq_number):
        message = (seq_number, sign(self.private_key, seq_number), self.cert_pem)
        return message

    def concession(self):
        pass

    def run_delegation_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            ssl_sock = ssl.wrap_socket(sock, keyfile=self.blockchain_key_path,
                                       certfile=self.blockchain_cert_path, server_side=True,
                                       do_handshake_on_connect=True)
            ssl_sock.bind(('localhost', blockchain_send_delegation_port))
            ssl_sock.listen()
            while True:
                conn, addr = ssl_sock.accept()
                with conn:
                    print(f'Connected by {addr} to send delegation')
                    data = conn.recv(4096)
                    delegation = pickle.loads(data)
                    ack = self.handle_delegation(delegation)
                    if ack:
                        conn.sendall(pickle.dumps(ack))
                    else:
                        conn.sendall(pickle.dumps("Invalid Request"))


if __name__ == '__main__':
    block_chain = BlockChain()
    thread = Thread(target=block_chain.run_delegation_server())
    thread.start()

