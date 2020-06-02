"""Create Cert."""
from OpenSSL import crypto
from os import getcwd
from pathlib import Path


CERT_FILE = 'ssl.crt'
KEY_FILE = 'ssl.key'


def create_ssl_cert(cn):
    """create ssl cert"""
    """https://dev.classmethod.jp/articles/create-x-509-v3-cert-python/"""

    # ".ssl dir"
    ssl_dir = Path(getcwd(), ".ssl")
    ssl_dir.mkdir(mode=0o700, exist_ok=True)

    # save cert
    certfile = Path(ssl_dir, CERT_FILE)
    keyfile = Path(ssl_dir, KEY_FILE)

    if certfile.exists() and keyfile.exists():
        return (str(keyfile), str(certfile))

    # create key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # create self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = 'JP'
    cert.get_subject().ST = 'test'
    cert.get_subject().L = 'test'
    cert.get_subject().OU = 'test'
    cert.get_subject().CN = cn
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.add_extensions([
        crypto.X509Extension(
            'basicConstraints'.encode('ascii'), False,
            'CA:FALSE'.encode('ascii')),
        crypto.X509Extension(
            'keyUsage'.encode('ascii'), True,
            'Digital Signature, Non Repudiation'.encode('ascii')),
        crypto.X509Extension(
            'extendedKeyUsage'.encode('ascii'), True,
            'serverAuth'.encode('ascii')),
        crypto.X509Extension(
            'issuerAltName'.encode('ascii'), False,
            'email:'.encode('ascii') + 'test'.encode('ascii'))
    ])
    # v3
    cert.set_version(2)
    # self signature
    cert.sign(key, 'sha256')

    # save cert
    with certfile.open(mode='wt') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
    certfile.chmod(0o600)

    # save private key
    with keyfile.open(mode='wt') as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8'))
    keyfile.chmod(0o600)

    return (keyfile, certfile)


if __name__ == '__main__':
    k, f = create_ssl_cert('ssl')
    print(k, f)
