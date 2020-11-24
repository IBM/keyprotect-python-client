#!/usr/bin/env python

from __future__ import print_function

import logging
import os
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

    key = kp.create(name="MyTestKey", root=True)
    print("Created key '%s'" % key['id'])

    print("Setting key rotation policy")
    set_key_rotation_policy = kp.set_key_rotation_policy(key['id'], 2)
    print("key %s rotation policy: %s" % (key['id'], set_key_rotation_policy['resources'][0]['rotation']))

    print("Setting key dual auth delete policy")
    set_key_dual_auth_policy = kp.set_key_dual_auth_policy(key['id'], True)
    print("key %s dual auth delete policy: %s" % (key['id'], set_key_dual_auth_policy['resources'][0]['dualAuthDelete']))

    print("Retrieving key policies for key %s:" % key['id'])
    key_policies_get = kp.get_key_policies(key['id'])
    print(key_policies_get)

    print("Setting instance dual auth delete policy to true")
    kp.set_instance_dual_auth_policy(True)

    print("Setting instance allowed network policy to public-and-private")
    kp.set_instance_allowed_network_policy(True, "public-and-private")

    print("Retrieving instance policies for instance %s:" % service_id)
    instance_policies_get = kp.get_instance_policies()
    print(instance_policies_get)

    # Example:
    # print("Setting instance allowed IP policy")
    # kp.set_instance_allowed_ip_policy(True, ["X.X.X.X/N", "X.X.X.X/N"])


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    try:
        main()
    except Exception as ex:
        traceback.print_exc()
        if hasattr(ex, "raw_response"):
            print(ex.raw_response)
