import os
from threading import Thread

from ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, \
    get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign, get_public_key_object_from_public_byte
from collections import defaultdict
from const import certs_path, blockchain_send_delegation_port, blockchain_send_transaction_port
from datetime import datetime
import socket, ssl, pickle
import uuid

class BlockChain:
    def __init__(self, name='BlockChain'):
        self.key_path = certs_path + "blockchain.key"
        self.cert_path = certs_path + "blockchain.cert"
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
        self.blocks = defaultdict(dict)
        self.bank_transactions = defaultdict(int)  # key: pk_wallet + pk_bank , value: last transaction seq number

    def add_new_block(self, bank_public, wallet_public, policy):
        key = (bank_public, wallet_public)
        if key in self.blocks and self.blocks[key]['timestamp'] > datetime.now().timestamp():
            return False
        range, count, timestamp, seq_number = policy.split('||')

        # possibly replay attack (we are waiting for last_seq_number + 1)
        if key in self.blocks and self.blocks[key]['seq_number'] != seq_number - 1:
            return False
        self.blocks[key] = {
            'range': float(range),
            'count': int(count),
            'timestamp': float(timestamp),
            'seq_number': int(seq_number)
        }
        return True

    def concession(self, pk_wallet, pk_bank, value):
        key = (pk_bank.decode('utf-8'), pk_wallet.decode('utf-8'))
        if key in self.blocks:
            if self.blocks[key]['timestamp'] > datetime.now().timestamp() and self.blocks[key]['count'] > 0 and \
                    self.blocks[key]['range'] > 0:
                self.blocks[key]['count'] -= 1
                self.blocks[key]['range'] -= value
                return True
        return False

    # p1.2
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

    # p1.2
    def ack_delegation(self, seq_number):
        message = (seq_number, sign(self.private_key, seq_number), self.cert_pem)
        return message

    # p4.4
    def perform_transaction(self, message):
        is_valid = True
        pk_wallet, pk_bank, transaction, signed_message = message
        key = (pk_bank, pk_wallet)
        crypto_amount, seq_number = transaction.decode().split("||")
        if key in self.bank_transactions and int(seq_number) != 1 + int(self.bank_transactions[key]):
            is_valid = False
        self.bank_transactions[key] = seq_number
        if not self.concession(pk_wallet, pk_bank, float(crypto_amount)):
            is_valid = False
        resp_to_bank = self.transaction_resp_to_bank(is_valid, seq_number)
        return is_valid, resp_to_bank

    # helper method for p4.4
    def transaction_resp_to_bank(self, validate, seq_number):
        if validate is True:
            msg = "success" + str(uuid.uuid4().int) + "||" + str(seq_number)
        else:
            msg = "success" + str(uuid.uuid4().int) + "||" + str(seq_number)
        return msg.encode("utf-8") , sign(self.private_key, msg.encode("utf-8")), self.cert_pem



    def run_delegation_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            ssl_sock = ssl.wrap_socket(sock, keyfile=self.key_path,
                                       certfile=self.cert_path, server_side=True,
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

    def run_transaction_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            ssl_sock = ssl.wrap_socket(sock, keyfile=self.key_path,
                                       certfile=self.cert_path, server_side=True,
                                       do_handshake_on_connect=True)
            ssl_sock.bind(('localhost', blockchain_send_transaction_port))
            ssl_sock.listen()
            while True:
                conn, addr = ssl_sock.accept()
                with conn:
                    print(f'Connected by {addr} to send transaction')
                    data = conn.recv(4096)
                    transaction = pickle.loads(data)
                    is_valid, ack = self.perform_transaction(transaction)
                    if is_valid:
                        conn.sendall(pickle.dumps(ack))
                    else:
                        conn.sendall(pickle.dumps("Invalid Request"))


if __name__ == '__main__':
    block_chain = BlockChain()
    Thread(target=block_chain.run_delegation_server).start()
    Thread(target=block_chain.run_transaction_server).start()


