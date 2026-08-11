# IBM Cloud Python SDK Version 3.0.0

# keyprotect-python-client

[![PyPi](https://img.shields.io/pypi/v/keyprotect.svg)](https://pypi.org/project/keyprotect)
[![Downloads](https://static.pepy.tech/personalized-badge/ibmcloud-iam?period=total&units=international_system&left_color=grey&right_color=orange&left_text=Downloads)](https://pepy.tech/project/keyprotect)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://travis-ci.com/IBM/keyprotect-python-client.svg?branch=master)](https://travis-ci.com/IBM/keyprotect-python-client)

A Pythonic client for IBM Key Protect

The client works with Python 3.9 or higher

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
import io
import json
import os

from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
from keyprotect.ibm_key_protect_api_v2 import IbmKeyProtectApiV2

# ---------------------------------------------------------------------------
# Configuration — set these environment variables before running:
#   IBMCLOUD_API_KEY   : your IBM Cloud IAM API key
#   KP_INSTANCE_ID     : the GUID of your Key Protect service instance
#   KP_URL (optional)  : Key Protect endpoint, defaults to us-south
# ---------------------------------------------------------------------------

API_KEY = os.getenv("IBMCLOUD_API_KEY", <API_KEY>)
INSTANCE_ID = os.getenv("KP_INSTANCE_ID", <INSTANCE_ID>)
KP_URL = os.getenv("KP_URL", "https://us-south.kms.cloud.ibm.com")

# ---------------------------------------------------------------------------
# 1. Build the authenticated service client
# ---------------------------------------------------------------------------

authenticator = IAMAuthenticator(apikey=API_KEY)
kp = IbmKeyProtectApiV2(authenticator=authenticator)
kp.set_service_url(KP_URL)

# ---------------------------------------------------------------------------
# 2. Create a root key  (extractable=False makes it a root / non-exportable key)
# ---------------------------------------------------------------------------

key_create_body = {
    "metadata": {
        "collectionType": "application/vnd.ibm.kms.key+json",
        "collectionTotal": 1,
    },
    "resources": [
        {
            "type": "application/vnd.ibm.kms.key+json",
            "name": "my-sample-root-key",
            "description": "Root key created by test.py sample",
            "extractable": False,  # False == root key (used for wrap/unwrap)
        }
    ],
}

response = kp.create_key(
    bluemix_instance=INSTANCE_ID,
    key_create_body=io.BytesIO(json.dumps(key_create_body).encode("utf-8")),
    prefer="return=representation",
)
key_data = response.get_result().json()
key_id = key_data["resources"][0]["id"]
print(f"[+] Created root key  id={key_id}")

# ---------------------------------------------------------------------------
# 3. Wrap a plaintext DEK (data-encryption key) with the root key
#    plaintext must be a base64-encoded 128, 192, or 256-bit value.
#    Here we supply a 128-bit (16-byte) example; omitting plaintext lets
#    Key Protect generate a DEK for you.
# ---------------------------------------------------------------------------

import base64

plaintext_dek = base64.b64encode(b"0123456789abcdef").decode()  # 16-byte key → base64

wrap_body = {"plaintext": plaintext_dek}

response = kp.wrap_key(
    id=key_id,
    bluemix_instance=INSTANCE_ID,
    key_action_wrap_body=io.BytesIO(json.dumps(wrap_body).encode("utf-8")),
)
wrap_result = response.get_result().json()
ciphertext = wrap_result["ciphertext"]
print(f"[+] Wrapped  ciphertext (first 60 chars): {ciphertext[:60]}…")

# ---------------------------------------------------------------------------
# 4. Unwrap — recover the original plaintext DEK from the ciphertext
# ---------------------------------------------------------------------------

unwrap_body = {"ciphertext": ciphertext}

response = kp.unwrap_key(
    id=key_id,
    bluemix_instance=INSTANCE_ID,
    key_action_unwrap_body=io.BytesIO(json.dumps(unwrap_body).encode("utf-8")),
)
unwrap_result = response.get_result().json()
recovered_plaintext = unwrap_result["plaintext"]

assert recovered_plaintext == plaintext_dek, (
    "Unwrapped plaintext does not match original!"
)
print(f"[+] Unwrapped plaintext matches original ✓")
print("Sample complete.")

```

## Using custom endpoint (for HPCS, Private Endpoint, Satellite, and Stage/Test instances)

Custom endpoints are needed when using this Python client against an HPCS/Satellite/Private service instance.

The following example shows how to specify a custom service endpoint

```python
kp = keyprotect.Client(
    credentials=tm,
    region="<region>",
    service_instance_id=os.getenv("KP_INSTANCE_ID"),
    # Set custom service endpoint
    endpoint_url="https://private.us-south.kms.cloud.ibm.com"
)
```

## Testing

### Test Types

The SDK has three test suites:

| Suite | Location |
|---|---|
| Unit tests | `test/unit/test_unit_ibm_key_protect_api_v2.py` |
| Integration tests | `test/integration/test_ibm_key_protect_api_v2.py` |
| Example tests | `examples/test_ibm_key_protect_api_v2_examples.py` |

### Setup

This project uses [uv](https://docs.astral.sh/uv/) for dependency management. Install it if you haven't already:

```bash
# macOS (Homebrew)
brew install uv

# or via the installer script
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then sync the lockfile to create a virtual environment with all dev dependencies:

```bash
uv sync --group dev
```

### Integration & Example Test Environment Setup

Integration and example tests run against `test.cloud.ibm.com`. Create an
`ibm_key_protect_api_v2.env` file in the `keyprotect-python-client` root with
the following values:

```text
IBM_KEY_PROTECT_API_URL=https://qa.us-south.kms.test.cloud.ibm.com
IBM_KEY_PROTECT_API_AUTH_URL=https://iam.test.cloud.ibm.com/identity/token
IBM_KEY_PROTECT_API_AUTH_TYPE=iam
IBM_KEY_PROTECT_API_APIKEY=<your-api-key>
IBM_KEY_PROTECT_API_BLUEMIX_INSTANCE=<your-instance-id>
```

If your integration or example test file requires unique resource names, assign
them manually in the test class setup:

```python
cls.created_keyring_id = "test-keyring"
cls.kmip_name         = "test-kmip"
cls.kmip_cert_name    = "Test-certificate"
```

### Running Tests

All `pytest` commands can be run in two ways — pick whichever you prefer:

| Style | When to use |
|---|---|
| `uv run pytest …` | No need to activate the venv; uv handles it |
| `source .venv/bin/activate && pytest …` | Activate once, then run pytest directly |

```bash
# Run all unit, integration, and example tests
uv run pytest

# Run only unit tests
uv run pytest test/unit/test_unit_ibm_key_protect_api_v2.py

# Run only integration tests
uv run pytest test/integration/test_ibm_key_protect_api_v2.py

# Run only example tests
uv run pytest examples/test_ibm_key_protect_api_v2_examples.py

# Run a specific unit test
uv run pytest test/unit/test_unit_ibm_key_protect_api_v2.py::TestIbmKeyProtectApiV2::<test-name>

# Run a specific integration test
uv run pytest test/integration/test_ibm_key_protect_api_v2.py::TestIbmKeyProtectApiV2::<test-name>

# Run a specific example test
uv run pytest examples/test_ibm_key_protect_api_v2_examples.py::TestIbmKeyProtectApiV2Examples::<test-name>

# Example
uv run pytest test/integration/test_ibm_key_protect_api_v2.py::TestIbmKeyProtectApiV2::test_create_key

# Use -v -rs flags for more verbose output
```
