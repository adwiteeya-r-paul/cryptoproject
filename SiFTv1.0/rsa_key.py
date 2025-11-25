from Crypto.PublicKey import RSA

keypair = RSA.generate(2048)

public_private_keypair = keypair.export_key(format='PEM', passphrase='Applied_Crypto_Project_Fall_2025').decode('ASCII')

with open('server_keypair_file.pem', 'w') as f:
    f.write(public_private_keypair)

public_key = keypair.publickey().export_key(format='PEM').decode('ASCII')

with open('server_public_key.pem', 'w') as f:
    f.write(public_key)