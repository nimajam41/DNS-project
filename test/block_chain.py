from classes.blockchain import BlockChain
from classes.const import cert_file
from classes.ca import get_public_key_byte_from_cert_file
import unittest


class TestBlockChain(unittest.TestCase):
    def setUp(self) -> None:
        bank_public_key_file = get_public_key_byte_from_cert_file(cert_file)
        message_to_sign = (bank_public_key_file.decode() + "||" + b'200||2||18526220589.27749||12').encode('utf-8')
        self.delegation = (
        get_public_key_byte_from_cert_file(cert_file),
        b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5YE+xmaQ4TMKlv6/rGw5\nYGRSOSDR/2uXozwO/Vr8PYUr6YyE8WGlfnr3IqXRT2skP2isMV89yTYeHIO/2lhy\nfgSfmkvZeScGK6fawNflmAxESxVI2sqE2FeauoKBM0QGOXNlJ7Aa8ZUfIBF2TE/I\nS4isAqrUuEOK43b8EOno2NMRlkPxuOJnE0bq2MYH16B0xRNEcuYLt910NAwlusLF\nQlwFjUxt2L8+H7SCdLh568TJyi2iO0oSw38jayxMXZaayN5vogXxUK0+3airqaJq\nRGwkjnZY2eQzx7vb/CueeV/PAsX+cGjHas9IMGKh66llaEp2l0AM9m1sU58yvupU\njwIDAQAB\n-----END PUBLIC KEY-----\n',
        b'200||2||18526220589.27749||12',
        b'\x08\x104y\xd8_\x8b\xd8\xd1\xce\xea\xb9\x96h\x9c\xaah\xb4\xe1m\x87\xf07\xf42\xd1n\x88\xd5\x0c\xf2\x99\xa0X\x0c\x8f\xa3Zs.\x11\xfap\x81\x9c\xcf\xd7+|8,\x83J\x93TB\x07\xc3\x93\xfb\xc9\xc3\x99d\xc1\xf8\xcfI\xb3\x8e[\x02\x8c0\xa2\x82]!\xf3#\x11\xbd\xb3\x19\x11\x1d\xf91\xa3\x13f\xef2"\xa6,g\x9a\xfd\xd9\x06\xc8\xa1\xcf\xaee\x101>\xd5\x81\xfb\xf5\xac\xf5\x17\x88\xb8i.W\xdd\x0e\xbd\xfb-\x1aq\xf4S!\xfa\nc\x1an\xf2\x05\x1a\x12"P2h\xce\x95\xa8\xa8\xd9\xc4\xebW\xfa\x96\xaa00\xefY\x15\xf0\xd8\xf8\xe8\xdb\xf8v3 \xe9\rv\xccY\xea%\xa3%\xf0T\x9fP\xf5\xb7\xd8\x13\x16|\xb3\x1ajP`\xb4:\xe8\xc50\xa4y\xc3\x16)K?D\x02}\x14\x1bM\xa1O\x01\x18\xe0\xb8+1\x0e\xac\xce\xff9\xe2t\xb9\xa6l$:js4\xe5\x17W\xd1\x9fT\x0e\xf7u\xfc\xd2\x8a\x8a8*\xb0\xc7\x02<%{\x96')
        self.block_chain = BlockChain()

    def test_validate_delegation(self):
        output1 = self.block_chain.handle_delegation(self.delegation)
        print(output1)
        self.assertIsNotNone(output1)
        # cant create new
        self.assertIsNone(self.block_chain.handle_delegation(self.delegation))
        self.assertEqual(len(self.block_chain.blocks), 1)

    def test_add_new_block(self):
        self.block_chain.handle_delegation(self.delegation)
        self.assertEqual(len(self.block_chain.blocks), 1)

    def test_ack_delegation(self):
        acked_message = self.block_chain.ack_delegation(b'10')
        self.assertIsNotNone(acked_message)
        self.assertEqual(acked_message[2], self.block_chain.cert_pem)
        self.assertEqual(acked_message[0], b'10')