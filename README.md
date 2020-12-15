# keyprotect-python-client

[![Build Status](https://travis-ci.com/IBM/keyprotect-python-client.svg?branch=master)](https://travis-ci.com/IBM/keyprotect-python-client)
[![Apache License](http://img.shields.io/badge/license-APACHE2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)

A Pythonic client for IBM Key Protect

This is a thin wrapper around the KeyProtect client in the [redstone](https://github.com/IBM/redstone) Python package. For detailed documentation and API references, please see the [redstone docs](https://redstone-py.readthedocs.org)

# Installation

The client is available on PyPI as the `keyprotect` package and is installable via `pip`:

```sh
pip install -U keyprotect
```

# Usage

The following python is a quick example of how to use the keyprotect module.

The example expects `IBMCLOUD_API_KEY` to be set to a valid IAM API key,
and `KP_INSTANCE_ID` to be set to the UUID identifying your KeyProtect instance.

```python
import os

import keyprotect
from keyprotect import bxauth


tm = bxauth.TokenManager(api_key=os.getenv("IBMCLOUD_API_KEY"))

kp = keyprotect.Client(
    credentials=tm,
    region="us-south",
    service_instance_id=os.getenv("KP_INSTANCE_ID")
)

for key in kp.keys():
    print("%s\t%s" % (key["id"], key["name"]))

key = kp.create(name="MyTestKey")
print("Created key '%s'" % key['id'])

kp.delete(key_id=key.get('id'))
print("Deleted key '%s'" % key['id'])


# wrap and unwrap require a non-exportable key,
# these are also referred to as root keys
key = kp.create(name="MyRootKey", root=True)

# wrap/unwrap, payload should be a bytestring if python3
message = b'This is a really important message.'
wrapped = kp.wrap(key_id=key.get('id'), plaintext=message)
ciphertext = wrapped.get("ciphertext")

unwrapped = kp.unwrap(key_id=key.get('id'), ciphertext=ciphertext)
assert message == unwrapped

# wrap/unwrap with AAD
message = b'This is a really important message too.'
wrapped = kp.wrap(key_id=key.get('id'), plaintext=message, aad=['python-keyprotect'])
ciphertext = wrapped.get("ciphertext")

unwrapped = kp.unwrap(key_id=key.get('id'), ciphertext=ciphertext, aad=['python-keyprotect'])
assert message == unwrapped
```

# Using custom endpoint

The following example shows how to use custom service endpoint

```python
kp = keyprotect.Client(
    credentials=tm,
    region="<region>",
    service_instance_id=os.getenv("KP_INSTANCE_ID"),
    # Set custom service endpoint
    endpoint_url="https://private.us-south.kms.cloud.ibm.com"
)
```