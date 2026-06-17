#!/usr/bin/env python
"""
install_cacerts_der.py - Install modern root CA certs into Snow Leopard keychain.
Uses DER format (base64-decoded from PEM) which CSSM handles correctly.
"""
import subprocess
import os
import tempfile
import base64

PEM_BUNDLE = '/tmp/cacert.pem'
KEYCHAIN = '/System/Library/Keychains/SystemRootCertificates.keychain'

def split_pem_to_der(bundle_path):
    """Extract DER bytes from each cert in a PEM bundle."""
    certs = []
    with open(bundle_path, 'r') as f:
        content = f.read()

    parts = content.split('-----BEGIN CERTIFICATE-----')
    for i, part in enumerate(parts[1:]):
        end = part.find('-----END CERTIFICATE-----')
        if end == -1:
            continue
        b64 = part[:end].strip().replace('\n', '').replace('\r', '')
        try:
            der = base64.b64decode(b64)
            certs.append(('cert_%d' % i, der))
        except Exception:
            continue
    return certs

def install_cert_der(name, der_data):
    """Write DER cert to temp file and install into keychain."""
    tmp = tempfile.NamedTemporaryFile(suffix='.der', delete=False)
    tmp.write(der_data)
    tmp.close()
    try:
        rc = subprocess.call([
            'security', 'add-trusted-cert',
            '-d',
            '-r', 'trustRoot',
            '-k', KEYCHAIN,
            tmp.name
        ], stdout=open('/dev/null', 'w'), stderr=open('/dev/null', 'w'))
        return rc == 0
    except Exception:
        return False
    finally:
        os.unlink(tmp.name)

def main():
    print('Splitting CA bundle into DER certs...')
    certs = split_pem_to_der(PEM_BUNDLE)
    print('Found %d certificates' % len(certs))

    installed = 0
    failed = 0
    for i, (name, der) in enumerate(certs):
        if install_cert_der(name, der):
            installed += 1
            if installed % 20 == 0:
                print('  installed %d/%d...' % (installed, len(certs)))
        else:
            failed += 1

    print('Done: %d installed, %d failed/skipped' % (installed, failed))

    # Verify GTS Root R1 is valid
    print('\nVerifying GTS Root R1...')
    r = subprocess.Popen(
        ['security', 'find-certificate', '-a', '-c', 'GTS Root R1',
         KEYCHAIN],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = r.communicate()
    if 'GTS' in out:
        print('GTS Root R1 found in keychain')
    else:
        print('GTS Root R1 NOT found')

if __name__ == '__main__':
    main()
