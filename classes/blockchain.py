from classes.ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign, get_public_key_object_from_public_byte
from collections import defaultdict
from classes.const import pk_bank_byte
from datetime import datetime


class BlockChain:
    def __init__(self, name='BlockChain'):
        self.cert_pem, private_key_byte = generate_selfsigned_cert(subject_name=name)
        self.public_key = get_public_key_object_from_cert_file(self.cert_pem), get_private_key_object_from_private_byte(
            private_key_byte)
        self.private_key = get_private_key_object_from_private_byte(private_key_byte)
        self.blocks = defaultdict(dict)

    def add_new_block(self, bank_public, wallet_public, policy):
        key = (bank_public, wallet_public)
        if key in self.blocks and float(self.blocks[key]['timestamp']) > datetime.now().timestamp():
            return False
        range, count, timestamp, _ = policy.split('||')
        self.blocks[key] = {
            'range': range,
            'count': count,
            'timestamp': timestamp
        }
        return True

    def handle_delegation(self, delegation_message):
        delegation_request_valid = True
        pk_file_bank, pk_wallet_user, policy, signed_message = delegation_message
        wallet_pk_object = get_public_key_object_from_public_byte(pk_wallet_user)
        if pk_file_bank != pk_bank_byte:
            delegation_request_valid = False
        elif not validate_sign(wallet_pk_object, signed_message, (pk_file_bank.decode() + "||" + policy.decode()).encode('utf-8')):
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

if __name__ == '__main__':
    block_chain = BlockChain()
