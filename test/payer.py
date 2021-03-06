# from classes.payer import Payer
# import unittest
#
#
# class TestPayer(unittest.TestCase):
#     def setUp(self) -> None:
#         self.acked_message_blockchain = (
#             b'10',
#             b"\x13\xe5\x86\xbf\x0c\xc4\xf4\xaf{\x9a\xe7.6\x0e\xc7\x8b\x96\x9a0\xa2\x0c\xb2\xc6\x0e\x9ft\xfe)\x1c\xd7\xe9]\r2W\xcfR\x11A9\xaa5\xb6Nwe?\x14\x01\x98\x0e\x1c\xef\xe2k\x06I\x1e\xa0\xe3\xe0\xdf\xd4\xd3U\xd7\xed\x0e\x83C\xfd\xab\xf1\x01\x1e\xe6\xc1<\x11bdY\xa3/\xe3\x13\x86r\x08\xf0\x00\xea|d\x8dZ\x8f\xe4H\xce\xe7\x93\xfe\x80\xd6\xf5\xae\x00\x1d=\xd6\xda\xdd\x1a'=\xea\xb8\x08$7\xb1e\x1f\x91\xfc\x02\t\x7f\x1f\xb0\xa2!*\xe2G\x03\xf2\xef\xe8\xe8\xb7K\xc8<D\x91k\x95\x94%!\xe5\x0c\xd8\xe5\x8f\xf5\x95\xfb\xb1wx\xce\xfc\xf9\x1bc#\x7f\xbe\xc0\xe1\xd4\xfcy\xf2\xbb^zu\x1f\xe2f\xf8U|\xbb\x87\x84r0\x96\xc0\xd1\xb05\x92\xdc{\xf5\xf7\xfc\xc7\xa2\xce\xaf\x86ZL\x84b\x85\xb1\x98\xf1\xbb\x18\xf7\xae\x98\xc4\x9d\xb6K$\x0f\xfc\xa8\xb4>\xb8\x1f\xdc5\xe8|\x10\x9d\xcd\xf7h\xeevP\x85\xf9\x97P2\xdeyN\xf8`\x8d",
#             b'-----BEGIN CERTIFICATE-----\nMIICxDCCAaygAwIBAgICA+gwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwEcm9v\ndDAeFw0yMTA3MTQwMTM5MDhaFw0zMTA3MTIwMTM5MDhaMBUxEzARBgNVBAMMCkJs\nb2NrQ2hhaW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCyvo7PGE9G\nO0vQVYIgPplmyyQHOq6KY7bRkrgaryoabLUo3gRNgIGwHdBE0kkQeQdlduxKO7lA\nmNnYh510kOl87SznUbns5GkbvqPasRg+WBLE5KxyWiZOYDsJ9NiHm3KaoQ1TO09v\nYliMpjPbfkN1zQ3LGzWrpgNuttd/ISu/3AXIO9niZdvoLT2/1AmD7DrZtw+aGJah\nCSiTA9ZeKF6XyRZldPfJ6WZn/2dL9jd5BWLKlg4zUwwqMNnogdWkZ38WOaRdiEUP\nEgl3lVkjeV9I17RcRneXyTV3bgg+Ndjuu7KAEiqMHw3ccgEkejmQ8RqiAzGTA7qT\nR73o2hX73sDVAgMBAAGjJDAiMA8GA1UdEwQIMAYBAf8CAQAwDwYDVR0RBAgwBoIE\ncm9vdDANBgkqhkiG9w0BAQsFAAOCAQEABinIVyzuR20ocp9cILA5782fxlZNmLR9\nYVK8Rd8dOGFtyq0rsTm61Aq4gjxntufch7cnvq9Gpuq5waqTEGHsCOsNv1DQyBqW\n/Y/SOtOoCPs2nBLjabaceR7kVcGsf6KSJN3muP4AXul2WRKrEWnxqclc2/x/clmQ\nyiwAvxoOytbEB8vopC2q4MjwvF6YZLO2f+hW5fEtIPEFQL7ybjeyyxE4NEbDQZez\n01TVY29M6AD6vDddlE57TaxVbe9uw6Xbfyb3X4BVLTNpWWf3MwodUCRAxLEB7yFT\nCTG52+QaI7843ph6TKDFXhezMuDo8jqvXuQhxWOSOQ6bZObXGYfwMQ==\n-----END CERTIFICATE-----\n'
#         )
#         self.attacker_acked_message_blockchain = (
#             b'12',
#             b"\x13\xe5\x86\xbf\x0c\xc4\xf4\xaf{\x9a\xe7.6\x0e\xc7\x8b\x96\x9a0\xa2\x0c\xb2\xc6\x0e\x9ft\xfe)\x1c\xd7\xe9]\r2W\xcfR\x11A9\xaa5\xb6Nwe?\x14\x01\x98\x0e\x1c\xef\xe2k\x06I\x1e\xa0\xe3\xe0\xdf\xd4\xd3U\xd7\xed\x0e\x83C\xfd\xab\xf1\x01\x1e\xe6\xc1<\x11bdY\xa3/\xe3\x13\x86r\x08\xf0\x00\xea|d\x8dZ\x8f\xe4H\xce\xe7\x93\xfe\x80\xd6\xf5\xae\x00\x1d=\xd6\xda\xdd\x1a'=\xea\xb8\x08$7\xb1e\x1f\x91\xfc\x02\t\x7f\x1f\xb0\xa2!*\xe2G\x03\xf2\xef\xe8\xe8\xb7K\xc8<D\x91k\x95\x94%!\xe5\x0c\xd8\xe5\x8f\xf5\x95\xfb\xb1wx\xce\xfc\xf9\x1bc#\x7f\xbe\xc0\xe1\xd4\xfcy\xf2\xbb^zu\x1f\xe2f\xf8U|\xbb\x87\x84r0\x96\xc0\xd1\xb05\x92\xdc{\xf5\xf7\xfc\xc7\xa2\xce\xaf\x86ZL\x84b\x85\xb1\x98\xf1\xbb\x18\xf7\xae\x98\xc4\x9d\xb6K$\x0f\xfc\xa8\xb4>\xb8\x1f\xdc5\xe8|\x10\x9d\xcd\xf7h\xeevP\x85\xf9\x97P2\xdeyN\xf8`\x8d",
#             b'-----BEGIN CERTIFICATE-----\nMIICxDCCAaygAwIBAgICA+gwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwEcm9v\ndDAeFw0yMTA3MTQwMTM5MDhaFw0zMTA3MTIwMTM5MDhaMBUxEzARBgNVBAMMCkJs\nb2NrQ2hhaW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCyvo7PGE9G\nO0vQVYIgPplmyyQHOq6KY7bRkrgaryoabLUo3gRNgIGwHdBE0kkQeQdlduxKO7lA\nmNnYh510kOl87SznUbns5GkbvqPasRg+WBLE5KxyWiZOYDsJ9NiHm3KaoQ1TO09v\nYliMpjPbfkN1zQ3LGzWrpgNuttd/ISu/3AXIO9niZdvoLT2/1AmD7DrZtw+aGJah\nCSiTA9ZeKF6XyRZldPfJ6WZn/2dL9jd5BWLKlg4zUwwqMNnogdWkZ38WOaRdiEUP\nEgl3lVkjeV9I17RcRneXyTV3bgg+Ndjuu7KAEiqMHw3ccgEkejmQ8RqiAzGTA7qT\nR73o2hX73sDVAgMBAAGjJDAiMA8GA1UdEwQIMAYBAf8CAQAwDwYDVR0RBAgwBoIE\ncm9vdDANBgkqhkiG9w0BAQsFAAOCAQEABinIVyzuR20ocp9cILA5782fxlZNmLR9\nYVK8Rd8dOGFtyq0rsTm61Aq4gjxntufch7cnvq9Gpuq5waqTEGHsCOsNv1DQyBqW\n/Y/SOtOoCPs2nBLjabaceR7kVcGsf6KSJN3muP4AXul2WRKrEWnxqclc2/x/clmQ\nyiwAvxoOytbEB8vopC2q4MjwvF6YZLO2f+hW5fEtIPEFQL7ybjeyyxE4NEbDQZez\n01TVY29M6AD6vDddlE57TaxVbe9uw6Xbfyb3X4BVLTNpWWf3MwodUCRAxLEB7yFT\nCTG52+QaI7843ph6TKDFXhezMuDo8jqvXuQhxWOSOQ6bZObXGYfwMQ==\n-----END CERTIFICATE-----\n'
#         )
#         self.payment_request = (
#             b'88ec7410-a926-467e-a254-dbede767d4a9||245000||81927774087745099803928947832218634808385888264756455966990563258449863317564684907015783545696864005279951899960891132154100169696080424083182919929333649912328476683585054971990292313612901401469676008299384289280252998670854969635740620499948249973744036918655591389150836127168338458237536950261379362914',
#             b'FuA\xdb\x9e\x91as\x1e\xe1B\xd1b1f\xdc\xf7\x07}H\x13R=\xf3,\xe6\xdd\x7fC\x06p){@\xd1o[y; \xe2\x05c\x97)\xaf\x0c\xbe\xad\tR\x13<7\xad\x80\x17*\xba7\xc3m\x1ep\xe7js\xb2h\x10\xf2\x99\xb6q\x92\'\xea\x19\xad\xe5Xy\x8cn\xc4\x02U\xe6\x01\xc8\xdcDQ\xed\xcch\x9f\x15\x0c\xed7\xde\xb3\x95\x0c\xda\xa31\x17FRT\x08\x1d\x1f\xab7\x85)\xceF=\x1c^\xbbB2\x9ay9zFpiw\xe2\xd6\xaaM\x16*\x00\xf2\xf4\xb3\xe8\xc0B\xf4\xc6\x7f\xe9\x8d\x13\x97u\xb4\xac\xa1\xffN\xc3:\xba\xc1\x0c\x9eM\x95\xefW\xcd]\xc9\x07r\xbb!\\\x1e\xf9F\xae\xe3\x8c\x94X\x08J\x95\xe8\x8e\xdd\xdab\xf7\xb7\xa1\xf8\xa1\x1c\xc31=\x12K\x11\xa3\xdc\xb9\x0c\x00\x13a!!\x13G\x0f\xb2\xf74\xc1\x1eXZ!\xe4\xfe\x99\x8fm\x07\\\x82\xa3\xc1Km\xd2"\x07\xc4cjx\x1bLO\xfc\xbf/V\xd31\xfd',
#             b'-----BEGIN CERTIFICATE-----\nMIICwjCCAaqgAwIBAgICA+gwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwEcm9v\ndDAeFw0yMTA3MTQxNDEyMjdaFw0zMTA3MTIxNDEyMjdaMBMxETAPBgNVBAMMCG1l\ncmNoYW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsaelIxaBr/Hw\nHBSTdQI+Q49p0fyJLK12L41eAGY23bJl1IfRxvzTsIZYiz2eCpNaBPB4Hqn6Jw9e\nqBE7XmEujlYD3BlTjwxns5UKCZH9viXOuThdqAtMSdUjwPMda229+ed1xSuEf3IU\n3Mi2YVRh4BpNAU+tBGJ4qZjy5WtR3ZfRAvjG22H38b9KdrVfv/rBp1wAi06XmFEo\ngg1CitrgJmQhsEgaFewrUiKbM59o4veMakDJ94A0Cb0TtJO7fGJnS3Q1BSN8rvI1\nBuwRxW3l2aYNVFoyU3mbBesLn69hdsVdp5oy++9hjcu4sJ7RVUY4mnQomuP20ANd\n7eWd5U94ZwIDAQABoyQwIjAPBgNVHRMECDAGAQH/AgEAMA8GA1UdEQQIMAaCBHJv\nb3QwDQYJKoZIhvcNAQELBQADggEBAIzCzvF9qtNYkqyRzdTSNOx8jDu1ZXdu5LMV\nlOzQPTXxAvdPZiBFuCNRyGQ6/CtNwgrjtMUYyisq5g5V7WDDKL99ECGtlkGpWnX9\nbYqL2kwYvo/GRzfxBB+v0hS54KhJNwEsJqU9PycTmKtz3+YknXAklwhMNwCWZDN5\nNM4nI4K4ojFCgQF8U5d89z8Yd5dtD7MApFqCFSTSYGhezg79k5aCDG+yJNTkl/gk\nd/zNniaHeceID7Z2ojZNdwUoLCE96CIxTRo96XVYX0vq8Ya62EBa/VBK9W4039xz\n7ng63OwN7uDNS6l7Er/fNHrg/Bmk+VuAtXZF0iu174Evj+MU8tw=\n-----END CERTIFICATE-----\n'
#         )
#
#         self.attacker_payment_request = (
#             b'88ec7410-a926-467e-a254-dbede767d4a9||2453400',
#             b'\x99d\xd765\x88\xd5\xa1e\x155\x07\xfc\xb0\xb7\xe5\x90/\xb3\xda9\x19\xe7\xcdN|\x8aF@\xcd\xc5\x85x\x9b\xc5z4n\xe1\x19n/h\xb6\x0c\xda\xd9~=\xc3[\xe3\xfeI\tr\xd5\xb9U\xa4O\xc74r\x00>\x8f)(\xd3\xe6\xf6Ns\x0b#d\x96|\xa5\xf5]\xed\xea|\xb9\x82\x85\x89\xbe".\x8d\xb0\x00\xbe\x8c\xd5Y0\x9d\x0f;U,\x8c\xe2\x9a/N`P{\x9c\xf8\xf1\xd5\xe8(8GB0\xb7\xc5x\xdbI$\x00\xc5\xfe\x82\xfd\xdc\x8a\xf6\x83\xd5\xac\x04\xd6\x0c\x8e\x91\xa7-Wv\x90I\xd2\xcd\x9e~\x08\x86g\xe1\xeas\xf2\xc9\x8a\xc3\xe6\x823\xdfs\x8bT\x9e+\xd0C[\xb7\x1aK\xbdj\x05\xac-\'\xe6q\x91\xf3@F\xfeY\x1e\xce\x18)!\x10p\x081\xd1\x06U~t\xdc\xea\xb9m\x84\xfe\x92g\xa6\xc4\x0c\xa0u5\x14\xf7\xde\xe9\xf8\x81\xe1\xfb/\xc0\xe9\x13\xd3\x93|\x01\x94\x94\\\xbd\x0f#o\x11\'\xff\xdb\xb9\x1c4k=\xffw',
#             b'-----BEGIN CERTIFICATE-----\nMIICwjCCAaqgAwIBAgICA+gwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwEcm9v\ndDAeFw0yMTA3MTQwMjAxMzZaFw0zMTA3MTIwMjAxMzZaMBMxETAPBgNVBAMMCG1l\ncmNoYW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAntk9XWnS97tE\nKUy9cbYn8d9zzlYLrZDj/iiMgWYfP1zeISy2Nhwe6jCLrzUcRI4t+CxRSvjwRxyE\nRVNfBo6gNu0ga48+arm3GzykyMSMCcuraAEIQNwY3SBT55Q1gJsSxIWUI8ExJ8Tm\naVY1hUEl9JSJsUw1Ye8TEZ/pL1V7wzJNdm5aMrG4iMoz/ODR/fKLaLl5rWG/grAv\ndifhIFpVZ1OaXhQfxId64Qq4VJRyLorYzJpCKTIbV4CV+7WdORmrV/XK+Fn3MIQ9\ncVqkOslrNHoDI/gQ9e3Wr9WQmYsEvvu8hK32Ct3JIr6PbhfeLEafXGZ0dYdtkjdI\n67K9xvEclQIDAQABoyQwIjAPBgNVHRMECDAGAQH/AgEAMA8GA1UdEQQIMAaCBHJv\nb3QwDQYJKoZIhvcNAQELBQADggEBACaHb9ffMap8GApztUgx3XRS7OYYGY4Sdq9r\nGcI5zAxpbuJtX6joJRLsFCcqho5gXO71v5Ozj1fCrp9Hf6GKxf1oeIHHuzBxQ/h3\n8wlNUNR1WGwlqesQ5fXsFFA+WK7uEzuZQKcGVpe7pGspkYU2FYpvMy3lt+imH+vz\neqy3JmOfltpNegHnvZBAByEQ3ZtOACxHv5u6B3Fh9A+nM7boJw+LEEz86YJjZO02\nNQla1YV6aWSrqDHHtPzLHu9YIO5Va0NsTyiJnD8l7eRfPtBYpC9YMtVm2QXFigV4\nuwDyyam0QYIqXTaZLsosOkr0x6SH7WvCREDvFId+9XvXj7isOvU=\n-----END CERTIFICATE-----\n'
#         )
#         self.payer = Payer()
#
#     def test_handle_delegation_ack_returns_true(self):
#         state = self.payer.handle_delegation_ack(self.acked_message_blockchain)
#         self.assertTrue(state)
#
#     def test_handle_delegation_ack_returns_false(self):
#         state = self.payer.handle_delegation_ack(self.attacker_acked_message_blockchain)
#         self.assertFalse(state)
#
#     def test_handle_payment_request_true(self):
#         state, nonce = self.payer.handle_payment_request(self.payment_request)
#         self.assertTrue(state)
#         self.assertIsNotNone(nonce)
#
#     def test_handle_payment_request_false(self):
#         state, nonce = self.payer.handle_payment_request(self.attacker_payment_request)
#         self.assertFalse(state)
#         self.assertIsNone(nonce)
