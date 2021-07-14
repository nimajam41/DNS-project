from classes.ca import generate_selfsigned_cert
cert_file, private_bank = generate_selfsigned_cert(subject_name='bank')

merchant_id = '88ec7410-a926-467e-a254-dbede767d4a9'
payer_id = '712d29cb-5f3e-46f3-826b-63cbf67c1947'

certs_path = "certs/"
blockchain_port = 8001