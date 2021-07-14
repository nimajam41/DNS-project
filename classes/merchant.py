from classes.ca import generate_selfsigned_cert, get_public_key_object_from_cert_file, \
    get_private_key_object_from_private_byte, \
    sign, get_public_key_byte_from_cert_file, validate_sign
from classes.const import merchant_id


class Merchant:
    def __init__(self, name='merchant'):
        self.cert_pem, private_key_byte = generate_selfsigned_cert(subject_name=name)
        self.public_key = get_public_key_object_from_cert_file(self.cert_pem)
        self.private_key = get_private_key_object_from_private_byte(private_key_byte)

    def create_payment_request(self, price):
        bill = merchant_id + "||" + str(price)
        bill = bill.encode('utf-8')
        signed_bill = sign(self.private_key, bill)
        return bill, signed_bill, self.cert_pem


if __name__ == '__main__':
    m = Merchant()
    x = m.create_payment_request(245000)
    print(x)
