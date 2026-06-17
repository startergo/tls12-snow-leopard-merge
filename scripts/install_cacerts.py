#!/usr/bin/env python
"""
install_cacerts.py - Install modern root CA certificates into Snow Leopard keychain.
Splits a PEM bundle (curl format) and installs each cert.
"""
import subprocess
import os
import tempfile

PEM_BUNDLE = '/tmp/cacert.pem'
KEYCHAIN = '/System/Library/Keychains/SystemRootCertificates.keychain'

def split_pem(bundle_path):
    certs = []
    with open(bundle_path, 'r') as f:
        content = f.read()

    # Split on BEGIN CERTIFICATE markers
    parts = content.split('-----BEGIN CERTIFICATE-----')
    for i, part in enumerate(parts[1:]):  # skip header
        end = part.find('-----END CERTIFICATE-----')
        if end == -1:
            continue
        cert_body = part[:end].strip()
        pem = '-----BEGIN CERTIFICATE-----\n' + cert_body + '\n-----END CERTIFICATE-----\n'

        # Try to find a name from preceding lines
        name = 'cert_%d' % i
        certs.append((name, pem))

    return certs

def install_cert(name, pem_data):
    tmp = tempfile.NamedTemporaryFile(suffix='.pem', delete=False, mode='w')
    tmp.write(pem_data)
    tmp.close()
    try:
        rc = subprocess.call([
            'security', 'add-trusted-cert',
            '-d', '-r', 'trustRoot',
            '-k', KEYCHAIN,
            tmp.name
        ], stdout=open('/dev/null', 'w'), stderr=open('/dev/null', 'w'))
        return rc == 0
    except Exception:
        return False
    finally:
        os.unlink(tmp.name)

def main():
    print('Splitting CA bundle...')
    certs = split_pem(PEM_BUNDLE)
    print('Found %d certificates' % len(certs))

    installed = 0
    failed = 0
    for i, (name, pem) in enumerate(certs):
        if install_cert(name, pem):
            installed += 1
            if installed % 20 == 0:
                print('  installed %d/%d...' % (installed, len(certs)))
        else:
            failed += 1

    print('Done: %d installed, %d failed/skipped' % (installed, failed))

if __name__ == '__main__':
    main()
