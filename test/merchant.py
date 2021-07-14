from classes.payer import Payer
from classes.merchant import Merchant
from classes.utils import generate_nonce
import unittest


class TestMerchant(unittest.TestCase):
    def setUp(self) -> None:
        self.nonce = generate_nonce()
        payer = Payer()
        self.acked_payment_request = payer.create_ack_payment_request(self.nonce + 1)
        self.attacker_acked_payment_request = payer.create_ack_payment_request(generate_nonce())
        self.merchant = Merchant()
        self.merchant.payment_req_nonce = self.nonce

    def test_handle_ack_payment_request_succeeds(self):
        is_valid = self.merchant.handle_ack_payment_request(self.acked_payment_request)
        self.assertTrue(is_valid)

    def test_handle_ack_payment_request_fails(self):
        is_valid = self.merchant.handle_ack_payment_request(self.attacker_acked_payment_request)
        self.assertFalse(is_valid)
