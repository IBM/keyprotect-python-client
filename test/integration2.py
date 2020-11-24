#!/usr/bin/env python

from __future__ import print_function

import logging
import os
import pprint
import time
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

    key = kp.create(name="MyTestKey", payload=b"Payload for test", root=True)
    print("Created key '%s'" % key['id'])

    kp.delete(key.get('id'))
    print("Deleted key '%s'" % key['id'])

    # restore
    time.sleep(31)
    kp.restore(key.get('id'), payload=b"Payload for test")
    print("Restored key '%s'" % key['id'])

    # disable
    kp.disable_key(key.get('id'))
    print("Disabled key '%s'" % key['id'])

    # enable
    time.sleep(31)
    kp.enable_key(key.get('id'))
    print("Enabled key '%s'" % key['id'])

    # create import token
    import_token = kp.create_import_token(86400, 50)
    print("Created import token: %r" % import_token)

    # get import token
    get_token = kp.get_import_token()
    print("Get import token: %r" % get_token)

    # sample for getting registrations associated with a key
    regs = kp.get_registrations(key['id'])
    print("Registrations: %r" % regs)

    #  sample for getting registrations associated with an instance
    all_regs = kp.get_registrations()
    print("All registrations: %r" % all_regs)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    try:
        main()
    except Exception as ex:
        traceback.print_exc()
        if hasattr(ex, "raw_response"):
            print(ex.raw_response)
