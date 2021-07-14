from classes.ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, \
    get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign
from classes.const import pk_bank_byte


class Payer:
    def __init__(self, name='payer'):
        self.cert_pem, private_key_byte = generate_selfsigned_cert(subject_name=name)
        self.public_key = get_public_key_object_from_cert_file(self.cert_pem), get_private_key_object_from_private_byte(
            private_key_byte)
        self.private_key = get_private_key_object_from_private_byte(private_key_byte)
        self.cert_pem_wallet, private_key_file_wallet = generate_selfsigned_cert(subject_name='wallet_' + name)
        self.public_key_wallet_byte = get_public_key_byte_from_cert_file(self.cert_pem_wallet)
        self.public_key_wallet = get_public_key_object_from_cert_file(self.cert_pem_wallet)
        self.private_key_wallet = get_private_key_object_from_private_byte(private_key_file_wallet)
        self.last_seq_number = '1'

    # we assume we have bank's pk
    def create_delegation(self, range, count, timestamp, seq_number, bank_public_key_file):
        policy = str(range) + "||" + str(count) + "||" + str(timestamp) + "||" + str(seq_number)
        policy = policy.encode('utf-8')
        message_to_sign = (bank_public_key_file.decode() + "||" + policy.decode()).encode('utf-8')
        self.last_seq_number = str(seq_number)
        return (
            bank_public_key_file, self.public_key_wallet_byte, policy, sign(self.private_key_wallet, message_to_sign))

    @staticmethod
    def handle_delegation_ack(message):
        seq_number, signed_message, pub_cer_blockchain = message
        pub_block_chain = get_public_key_object_from_cert_file(pub_cer_blockchain)
        if validate_sign(pub_block_chain, signed_message, seq_number):
            return True

        # inja age false bud bayad replay koni create_delegation va inaro dg
        return False

    # we assume price value is always correct (user will check it by its knowledge)
    def handle_payment_request(self, payment_request):
        bill, signed_bill, merchant_pk_certificate = payment_request
        merchant_pk = get_public_key_object_from_cert_file(merchant_pk_certificate)
        if validate_sign(merchant_pk, signed_bill, bill):
            return True
        return False

    # TODO: ack merchant that we confirm payment request


if __name__ == '__main__':
    p = Payer()

    # test_delegation
    print(p.create_delegation(200, 2, 18526220589.27749, 12, pk_bank_byte))
    pk_file, pk_wallet, policy, sign = p.create_delegation(200, 2, 1856220589.27749, 12, pk_bank_byte)
    print(pk_file)
    print(pk_wallet)
    print(policy)
    print(sign)
    # mock validate signed message
    print(validate_sign(p.public_key_wallet, sign, (pk_file.decode() + "||" + policy.decode()).encode('utf-8')))
