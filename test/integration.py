#!/usr/bin/env python

from __future__ import print_function

import logging
import os
import pprint
import traceback

import keyprotect
from keyprotect import bxauth


service_id = os.environ.get("KP_INSTANCE_ID")
region_name = os.environ.get("KP_INSTANCE_REGION") or "us-east"


env_vars = [os.environ.get('IBMCLOUD_API_KEY'),
            os.environ.get('BLUEMIX_API_KEY')]


# iterate through possible API key vars
# in order and use first one that is not nil/empty
for var in env_vars:
    if var:
        apikey = var
        break


def main():
    tm = bxauth.TokenManager(api_key=apikey)

    kp = keyprotect.Client(
        credentials=tm,
        region=region_name,
        service_instance_id=service_id,
    )

    for key in kp.keys():
        print("%s\t%s" % (key['id'], key['name']))

    key = kp.create(name="MyTestKey")
    print("Created key '%s'" % key['id'])

    print(kp.get(key.get('id')))

    kp.delete(key.get('id'))
    print("Deleted key '%s'" % key['id'])

    # wrap/unwrap/rewrap
    print("Creating root key")
    key = kp.create(name="MyRootKey", root=True)

    message = b'This is a really important message.'
    print("Wrapping message: %r" % message)
    wrapped = kp.wrap(key.get('id'), message)
    ciphertext = wrapped.get("ciphertext")

    print("Unwrapping message...")
    unwrapped = kp.unwrap(key.get('id'), ciphertext)
    print("Unwrapped plaintext: %r" % unwrapped)
    assert message == unwrapped

    rotated = kp.rotate(key.get('id'))
    if rotated == 'Success':
        print("Rotated key: %s" % key.get('id'))

    print("Rewrapping message...")
    rewrapped = kp.rewrap(key.get('id'), ciphertext)
    assert rewrapped['ciphertext'] != ciphertext

    kp.delete(key.get('id'))
    print("Deleted key '%s'" % key['id'])

    # wrap/unwrap/rewrap with AAD
    print("Creating root key")
    key = kp.create(name="MyRootKey", root=True)

    message = b'This is a really important message too.'
    print("Wrapping message: %r" % message)
    wrapped = kp.wrap(key.get('id'), message, aad=['python-keyprotect'])
    ciphertext = wrapped.get("ciphertext")

    print("Unwrapping message...")
    unwrapped = kp.unwrap(key.get('id'), ciphertext, aad=['python-keyprotect'])
    print("Unwrapped plaintext: %r" % unwrapped)
    assert message == unwrapped

    rotated = kp.rotate(key.get('id'))
    if rotated == 'Success':
        print("Rotated key: %s" % key.get('id'))

    print("Rewrapping message...")
    rewrapped = kp.rewrap(key.get('id'), ciphertext, aad=['python-keyprotect'])
    assert rewrapped['ciphertext'] != ciphertext

    kp.delete(key.get('id'))
    print("Deleted key '%s'" % key['id'])


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    try:
        main()
    except Exception as ex:
        traceback.print_exc()
        if hasattr(ex, "raw_response"):
            print(ex.raw_response)
