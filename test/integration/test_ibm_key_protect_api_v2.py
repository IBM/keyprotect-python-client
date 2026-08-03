# -*- coding: utf-8 -*-
# (C) Copyright IBM Corp. 2026.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Integration Tests for IbmKeyProtectApiV2
"""

from ibm_cloud_sdk_core import *
from keyprotect.ibm_key_protect_api_v2 import *
import io
import os
import pytest

# MANUAL: Added imports for JSON body construction, type hints, and rate limit handling
from ibm_cloud_sdk_core.detailed_response import DetailedResponse
from typing import Any
import json
import time
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa

# Config file name
config_file = "ibm_key_protect_api_v2.env"

# MANUAL: generateTestCertPEM produces a self-signed X.509 certificate in memory for testing
def generate_test_cert_pem() -> str:
    """Produce a self-signed X.509 certificate in memory, removing the need for
    a pre-generated temp.pem file or an external openssl invocation.
    Equivalent to:
        openssl req -x509 -newkey rsa:4096 -keyout key.pem -out temp.pem \\
          -sha256 -days 1 -nodes \\
          -subj "/C=XX/ST=XX/L=locality/O=company/OU=org/CN=CommonNameOrHostname"
    """
    key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "XX"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "locality"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "company"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "CommonNameOrHostname"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


class TestIbmKeyProtectApiV2:
    """
    Integration Test Class for IbmKeyProtectApiV2
    """

    @classmethod
    def setup_class(cls):
        if os.path.exists(config_file):
            os.environ["IBM_CREDENTIALS_FILE"] = config_file

            cls.ibm_key_protect_api_service = IbmKeyProtectApiV2.new_instance()
            assert cls.ibm_key_protect_api_service is not None

            cls.config = read_external_sources(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME)
            assert cls.config is not None

            cls.ibm_key_protect_api_service.enable_retries()

            # MANUAL: Added class variables for test state management and dependencies
            cls.created_keyring_id = "test-keyring"
            cls.kmip_name = "test-kmip"
            cls.kmip_cert_name = "Test-certificate"
            cls.bluemix_instance = cls.config.get("BLUEMIX_INSTANCE")
            cls.kmip_with_object = None
            cls.kmip_object = None
            cls.created_key_id = None
            cls.policies_overriden_key_id = None
            cls.ciphertext = None
            cls.disable_key_timestamp = None
            cls.delete_key_timestamp = None

        print("Setup complete.")

    needscredentials = pytest.mark.skipif(
        not os.path.exists(config_file),
        reason="External configuration not available, skipping...",
    )

    @needscredentials
    def test_get_key_collection_metadata(self):
        response = self.ibm_key_protect_api_service.get_key_collection_metadata(
            bluemix_instance=self.__class__.bluemix_instance,
            state=[0, 1, 2, 3],
            extractable=True,
        )

        print(f"Response body: {response.get_result()}")
        assert response.get_status_code() == 200

    @needscredentials
    def test_create_key(self):
        # Construct the key creation body
        key_create_body = {
            "metadata": {
                "collectionType": "application/vnd.ibm.kms.key+json",
                "collectionTotal": 1,
            },
            "resources": [
                {
                    "type": "application/vnd.ibm.kms.key+json",
                    "name": "created-test-root-key",
                    "description": "A Key Protect key used for integration testing",
                    "extractable": False,
                }
            ],
        }

        response = self.ibm_key_protect_api_service.create_key(
            bluemix_instance=self.__class__.bluemix_instance,
            key_create_body=io.BytesIO(json.dumps(key_create_body).encode("utf-8")),
            prefer="return=representation",
        )

        assert response.get_status_code() == 201
        key = response.get_result()
        key_data = key.json()
        key_id = key_data["resources"][0]["id"]

        # MANUAL: Store the key ID in class variable for use in test_delete_key
        self.__class__.created_key_id = key_id

        print(f"\nCreated Key ID: {key_id}\n")
        assert key_data is not None

    @needscredentials
    def test_get_keys(self):
        response = self.ibm_key_protect_api_service.get_keys(
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 200
        list_keys = response.get_result()
        assert list_keys is not None

    @needscredentials
    def test_create_key_with_policies_overrides(self):
        key_with_policy_overrides_create_body = {
            "metadata": {
                "collectionType": "application/vnd.ibm.kms.key+json",
                "collectionTotal": 1,
            },
            "resources": [
                {
                    "type": "application/vnd.ibm.kms.key+json",
                    "name": "policies-test-overriden-key",
                    "description": "A Key Protect key used for integration testing",
                    "extractable": False,
                    "dualAuthDelete": {"enabled": False},
                    "rotation": {"enabled": True, "interval_month": 6},
                }
            ],
        }

        response = self.ibm_key_protect_api_service.create_key_with_policies_overrides(
            bluemix_instance=self.__class__.bluemix_instance,
            key_with_policy_overrides_create_body=io.BytesIO(
                json.dumps(key_with_policy_overrides_create_body).encode("utf-8")
            ),
            prefer="return=representation",
        )

        assert response.get_status_code() == 201
        key = response.get_result()
        key_data: Any = key.json()
        key_id = key_data["resources"][0]["id"]

        # MANUAL: Store the key ID in class variable for use in test_delete_key
        self.__class__.policies_overriden_key_id = key_id

        assert key is not None

    @needscredentials
    def test_get_key(self):
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        response = self.ibm_key_protect_api_service.get_key(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 200
        get_key = response.get_result()
        assert get_key is not None

    @needscredentials
    def test_get_key_metadata(self):
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        response = self.ibm_key_protect_api_service.get_key_metadata(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 200
        get_key_metadata = response.get_result()
        assert get_key_metadata is not None

    @needscredentials
    def test_get_key_versions(self):
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        response = self.ibm_key_protect_api_service.get_key_versions(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
            limit=200,
            offset=0,
            total_count=True,
            all_key_states=False,
        )

        assert response.get_status_code() == 200
        list_key_versions = response.get_result()
        assert list_key_versions is not None

    @needscredentials
    def test_wrap_key(self):
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        key_action_wrap_body = {
            "plaintext": "cGxhaW50ZXh0LWRhdGEta2V5",
        }

        response = self.ibm_key_protect_api_service.wrap_key(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
            key_action_wrap_body=io.BytesIO(
                json.dumps(key_action_wrap_body).encode("utf-8")
            ),
        )

        assert response.get_status_code() == 200
        wrap_key_response_body = response.get_result()
        wrap_key_response_data: Any = wrap_key_response_body.json()
        ciphertext = wrap_key_response_data["ciphertext"]
        # MANUAL: Store ciphertext for use in unwrap/rewrap tests
        self.__class__.ciphertext = ciphertext
        assert wrap_key_response_body is not None

    @needscredentials
    def test_unwrap_key(self):
        # MANUAL: Use stored ciphertext from test_wrap_key
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        ciphertext = self.__class__.ciphertext
        if ciphertext is None:
            pytest.skip("No ciphertext available from test_wrap_key")

        key_action_unwrap_body = {
            "ciphertext": ciphertext,
        }

        response = self.ibm_key_protect_api_service.unwrap_key(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
            key_action_unwrap_body=io.BytesIO(
                json.dumps(key_action_unwrap_body).encode("utf-8")
            ),
        )

        assert response.get_status_code() == 200
        unwrap_key_response_body = response.get_result()
        assert unwrap_key_response_body is not None

    @needscredentials
    def test_rewrap_key(self):
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        ciphertext = self.__class__.ciphertext
        if ciphertext is None:
            pytest.skip("No ciphertext available from test_wrap_key")

        key_action_rewrap_body = {
            "ciphertext": ciphertext,
        }

        response = self.ibm_key_protect_api_service.rewrap_key(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
            key_action_rewrap_body=io.BytesIO(
                json.dumps(key_action_rewrap_body).encode("utf-8")
            ),
        )

        assert response.get_status_code() == 200
        rewrap_key_response_body = response.get_result()
        assert rewrap_key_response_body is not None

    @needscredentials
    def test_rotate_key(self):
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        key_action_rotate_body = {}

        response = self.ibm_key_protect_api_service.rotate_key(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
            key_action_rotate_body=io.BytesIO(
                json.dumps(key_action_rotate_body).encode("utf-8")
            ),
            prefer="return=representation",
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_disable_key(self):
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        response = self.ibm_key_protect_api_service.disable_key(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 204
        # MANUAL: Record timestamp for rate limit handling in test_enable_key
        self.__class__.disable_key_timestamp = time.time()

    @needscredentials
    def test_enable_key(self):
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        # MANUAL: Wait 31 seconds after disable to respect API rate limits
        if self.__class__.disable_key_timestamp is not None:
            elapsed = time.time() - self.__class__.disable_key_timestamp
            if elapsed < 31:
                time.sleep(31 - elapsed)

        response = self.ibm_key_protect_api_service.enable_key(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_put_policy(self):
        # MANUAL: Use policies_overriden_key_id instead of created_key_id
        key_id = self.__class__.policies_overriden_key_id

        if key_id is None:
            pytest.skip(
                "No key ID available from test_create_key_with_policies_overrides"
            )

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {
            "collectionType": "application/vnd.ibm.kms.policy+json",
            "collectionTotal": 1,
        }
        # Construct a dict representation of a KeyPolicyDualAuthDeleteDualAuthDelete model
        key_policy_dual_auth_delete_dual_auth_delete_model = {
            "enabled": False,  # MANUAL: Changed from True to False
        }
        # Construct a dict representation of a KeyPolicyDualAuthDelete model
        key_policy_dual_auth_delete_model = {
            "type": "application/vnd.ibm.kms.policy+json",
            "dualAuthDelete": key_policy_dual_auth_delete_dual_auth_delete_model,
        }
        # Construct a dict representation of a SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete model
        set_key_policies_one_of_model = {
            "metadata": collection_metadata_model,
            "resources": [key_policy_dual_auth_delete_model],
        }

        response = self.ibm_key_protect_api_service.put_policy(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
            key_policy_put_body=set_key_policies_one_of_model,
            policy="dualAuthDelete",
        )

        assert response.get_status_code() == 200
        get_key_policies_one_of = response.get_result()
        assert get_key_policies_one_of is not None

    @needscredentials
    def test_get_policy(self):
        key_id = self.__class__.policies_overriden_key_id

        if key_id is None:
            pytest.skip(
                "No key ID available from test_create_key_with_policies_overrides"
            )

        response = self.ibm_key_protect_api_service.get_policy(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
            policy="dualAuthDelete",
        )

        assert response.get_status_code() == 200
        get_key_policies_one_of = response.get_result()
        assert get_key_policies_one_of is not None

    @needscredentials
    def test_put_instance_policy(self):
        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {
            "collectionType": "application/vnd.ibm.kms.policy+json",
            "collectionTotal": 1,
        }
        # Construct a dict representation of a InstancePolicyAllowedNetworkPolicyDataAttributes model
        instance_policy_allowed_network_policy_data_attributes_model = {
            "allowed_network": "public-and-private",  # MANUAL: Changed from 'private-only'
        }
        # Construct a dict representation of a InstancePolicyAllowedNetworkPolicyData model
        instance_policy_allowed_network_policy_data_model = {
            "enabled": True,
            "attributes": instance_policy_allowed_network_policy_data_attributes_model,
        }
        # Construct a dict representation of a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem model
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model = {
            "policy_type": "allowedNetwork",
            "policy_data": instance_policy_allowed_network_policy_data_model,
        }
        # Construct a dict representation of a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork model
        set_instance_policies_one_of_model = {
            "metadata": collection_metadata_model,
            "resources": [
                set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model
            ],
        }

        response = self.ibm_key_protect_api_service.put_instance_policy(
            bluemix_instance=self.__class__.bluemix_instance,
            instance_policy_put_body=set_instance_policies_one_of_model,
            policy="allowedNetwork",
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_get_instance_policy(self):
        response = self.ibm_key_protect_api_service.get_instance_policy(
            bluemix_instance=self.__class__.bluemix_instance,
            policy="allowedNetwork",
        )

        assert response.get_status_code() == 200
        get_instance_policies_one_of = response.get_result()
        assert get_instance_policies_one_of is not None

    @pytest.mark.skip(
        reason="Skipping test_get_allowed_ip_port"
    )  # MANUAL: Added skip decorator
    @needscredentials
    def test_get_allowed_ip_port(self):
        response = self.ibm_key_protect_api_service.get_allowed_ip_port(
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 200
        allowed_ip_port = response.get_result()
        assert allowed_ip_port is not None

    @needscredentials
    def test_post_import_token(self):
        response = self.ibm_key_protect_api_service.post_import_token(
            bluemix_instance=self.__class__.bluemix_instance,
            expiration=600,
            max_allowed_retrievals=1,
        )

        assert response.get_status_code() == 200
        import_token = response.get_result()
        assert import_token is not None

    @needscredentials
    def test_get_import_token(self):
        response = self.ibm_key_protect_api_service.get_import_token(
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 200
        get_import_token = response.get_result()
        assert get_import_token is not None

    @needscredentials
    def test_get_registrations(self):
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        response = self.ibm_key_protect_api_service.get_registrations(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 200
        registration_with_total_count = response.get_result()
        assert registration_with_total_count is not None

    @needscredentials
    def test_get_registrations_all_keys(self):
        response = self.ibm_key_protect_api_service.get_registrations_all_keys(
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 200
        registration_with_total_count = response.get_result()
        assert registration_with_total_count is not None

    @needscredentials
    def test_create_key_alias(self):
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        response = self.ibm_key_protect_api_service.create_key_alias(
            id=key_id,
            alias="testString",
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 201
        key_alias = response.get_result()
        assert key_alias is not None

    @needscredentials
    def test_delete_key_alias(self):
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        response = self.ibm_key_protect_api_service.delete_key_alias(
            id=key_id,
            alias="testString",
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_list_key_rings(self):
        response = self.ibm_key_protect_api_service.list_key_rings(
            bluemix_instance=self.__class__.bluemix_instance,
            limit=100,
            offset=0,
            total_count=True,
        )

        assert response.get_status_code() == 200
        list_key_rings_with_total_count = response.get_result()
        assert list_key_rings_with_total_count is not None

    @needscredentials
    def test_get_kmip_adapters(self):
        response = self.ibm_key_protect_api_service.get_kmip_adapters(
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 200
        list_kmip_adapters_with_total_count = response.get_result()
        assert list_kmip_adapters_with_total_count is not None

    @needscredentials
    def test_create_key_ring(self):
        response = self.ibm_key_protect_api_service.create_key_ring(
            key_ring_id=self.__class__.created_keyring_id,
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 201
        key = response.get_result()

    @needscredentials
    def test_patch_key(self):
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        key_patch_body = {"keyRingID": self.__class__.created_keyring_id}

        response = self.ibm_key_protect_api_service.patch_key(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
            key_patch_body=io.BytesIO(json.dumps(key_patch_body).encode("utf-8")),
        )

        assert response.get_status_code() == 200
        patch_key_response_body = response.get_result()
        assert patch_key_response_body is not None

    @needscredentials
    def test_delete_key(self):
        # MANUAL: Moved test earlier in execution order
        # Use the key ID from test_create_key
        key_id = self.__class__.created_key_id

        # Skip if no key was created
        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        print(f"\n\nDeleting Key ID: {key_id}\n\n")

        response = self.ibm_key_protect_api_service.delete_key(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
            x_kms_key_ring=self.__class__.created_keyring_id,  # MANUAL: Kept x_kms_key_ring to delete from specific ring
            prefer="return=representation",
            force=False,
        )

        assert response.get_status_code() == 200
        delete_key = response.get_result()
        assert delete_key is not None

        print(f"\nSuccessfully deleted key: {key_id}\n")
        # MANUAL: Record timestamp for rate limit handling in test_restore_key
        self.__class__.delete_key_timestamp = time.time()

    @needscredentials
    def test_restore_key(self):
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        # MANUAL: Wait 31 seconds after delete to respect API rate limits
        if self.__class__.delete_key_timestamp is not None:
            elapsed = time.time() - self.__class__.delete_key_timestamp
            if elapsed < 31:
                time.sleep(31 - elapsed)

        response = self.ibm_key_protect_api_service.restore_key(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
            x_kms_key_ring=self.__class__.created_keyring_id,  # MANUAL: Kept x_kms_key_ring to restore to specific ring
            prefer="return=representation",
        )

        assert response.get_status_code() == 201
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_delete_key_ring(self):
        # MANUAL: Added logic to move key to default ring before deleting keyring
        # Move key to another key ring
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        key_patch_body = {"keyRingID": "default"}

        response = self.ibm_key_protect_api_service.patch_key(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
            x_kms_key_ring=self.__class__.created_keyring_id,  # MANUAL: Kept x_kms_key_ring to move key from specific ring
            key_patch_body=io.BytesIO(json.dumps(key_patch_body).encode("utf-8")),
        )

        assert response.get_status_code() == 200
        patch_key_response_body = response.get_result()
        assert patch_key_response_body is not None

        # Delete keyring

        key_ring_id = self.__class__.created_keyring_id

        if key_ring_id is None:
            pytest.skip("No key ring ID available from test_create_key_ring")

        response = self.ibm_key_protect_api_service.delete_key_ring(
            key_ring_id=key_ring_id,
            bluemix_instance=self.__class__.bluemix_instance,
            force=False,
        )

        assert response.get_status_code() == 204

    @pytest.mark.skip(reason="Skipping test_purge_key")  # MANUAL: Added skip decorator
    @needscredentials
    def test_purge_key(self):
        key_id = self.__class__.created_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        response = self.ibm_key_protect_api_service.purge_key(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
            x_kms_key_ring=self.__class__.created_keyring_id,
            prefer="return=representation",
        )

        assert response.get_status_code() == 200
        purge_key = response.get_result()
        assert purge_key is not None
        assert response.get_status_code() == 200
        registration = response.get_result()
        assert registration is not None

    @pytest.mark.skip(
        reason="Skipping test_set_key_for_deletion"
    )  # MANUAL: Added skip decorator
    @needscredentials
    def test_set_key_for_deletion(self):
        key_id = self.__class__.policies_overriden_key_id

        if key_id is None:
            pytest.skip(
                "No key ID available from test_create_key_with_policies_overrides"
            )

        response = self.ibm_key_protect_api_service.set_key_for_deletion(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 204

    @pytest.mark.skip(
        reason="Skipping test_unset_key_for_deletion"
    )  # MANUAL: Added skip decorator
    @needscredentials
    def test_unset_key_for_deletion(self):
        key_id = self.__class__.policies_overriden_key_id

        if key_id is None:
            pytest.skip(
                "No key ID available from test_create_key_with_policies_overrides"
            )

        response = self.ibm_key_protect_api_service.unset_key_for_deletion(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_sync_associated_resources(self):
        key_id = self.__class__.policies_overriden_key_id

        if key_id is None:
            pytest.skip("No key ID available from test_create_key")

        response = self.ibm_key_protect_api_service.sync_associated_resources(
            id=key_id,
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_create_kmip_adapter(self):
        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {
            "collectionType": "application/vnd.ibm.kms.kmip_adapter+json",
            "collectionTotal": 1,
        }
        # Construct a dict representation of a KMIPProfileDataBodyKMIPProfileDataNative model
        kmip_profile_data_body_model = {
            "crk_id": self.__class__.policies_overriden_key_id,  # MANUAL: Use policies_overriden_key_id
        }
        # Construct a dict representation of a CreateKMIPAdapterObject model
        create_kmip_adapter_object_model = {
            "name": self.__class__.kmip_name,
            "description": "Test KMIP adapter created by integration test",
            "profile": "native_1.0",
            "profile_data": kmip_profile_data_body_model,
        }

        response = self.ibm_key_protect_api_service.create_kmip_adapter(
            bluemix_instance=self.__class__.bluemix_instance,
            metadata=collection_metadata_model,
            resources=[create_kmip_adapter_object_model],
        )

        assert response.get_status_code() == 201
        list_kmip_adapters = response.get_result()
        assert list_kmip_adapters is not None

    @needscredentials
    def test_get_kmip_adapter(self):
        response = self.ibm_key_protect_api_service.get_kmip_adapter(
            id=self.__class__.kmip_name,
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 200
        list_kmip_adapters = response.get_result()
        assert list_kmip_adapters is not None

    @needscredentials
    def test_get_kmip_objects(self):
        response: DetailedResponse = self.ibm_key_protect_api_service.get_kmip_objects(
            adapter_id=self.__class__.kmip_name,
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 200
        list_kmip_objects_with_total_count = response.get_result()
        assert list_kmip_objects_with_total_count is not None

    @pytest.mark.skip(
        reason="Skipping test_get_kmip_object"
    )  # MANUAL: Added skip decorator
    @needscredentials
    def test_get_kmip_object(self):

        object_id = self.__class__.kmip_object
        if object_id is None:
            pytest.skip("No KMIP object available")

        response: DetailedResponse = self.ibm_key_protect_api_service.get_kmip_object(
            adapter_id=self.__class__.kmip_with_object,
            bluemix_instance=self.__class__.bluemix_instance,
            id=self.__class__.kmip_object,
        )

        assert response.get_status_code() == 200
        list_kmip_objects_with_total_count = response.get_result()
        assert list_kmip_objects_with_total_count is not None

    @needscredentials
    def test_get_kmip_client_certificates(self):
        response = self.ibm_key_protect_api_service.get_kmip_client_certificates(
            adapter_id=self.__class__.kmip_name,
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 200
        list_kmip_partial_client_certificates_with_total_count = response.get_result()
        assert list_kmip_partial_client_certificates_with_total_count is not None

    @needscredentials
    def test_add_kmip_client_certificate(self):
        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {
            "collectionType": "application/vnd.ibm.kms.kmip_client_certificate+json",
            "collectionTotal": 1,
        }

        # MANUAL: Generate certificate in memory instead of reading from temp.pem
        certificate = generate_test_cert_pem()

        # Construct a dict representation of a CreateKMIPClientCertificateObject model
        create_kmip_client_certificate_object_model = {
            "certificate": certificate,
            "name": self.__class__.kmip_cert_name,
        }

        response = self.ibm_key_protect_api_service.add_kmip_client_certificate(
            adapter_id=self.__class__.kmip_name,
            bluemix_instance=self.__class__.bluemix_instance,
            metadata=collection_metadata_model,
            resources=[create_kmip_client_certificate_object_model],
        )

        assert response.get_status_code() == 201
        list_kmip_client_certificates = response.get_result()
        list_certificates = list_kmip_client_certificates.json()
        print(list_certificates)
        assert list_kmip_client_certificates is not None

    @needscredentials
    def test_get_kmip_client_certificate(self):
        response = self.ibm_key_protect_api_service.get_kmip_client_certificate(
            adapter_id=self.__class__.kmip_name,
            id=self.__class__.kmip_cert_name,
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 200
        list_kmip_client_certificates = response.get_result()
        assert list_kmip_client_certificates is not None

    @needscredentials
    def test_delete_kmip_client_certificate(self):
        response = self.ibm_key_protect_api_service.delete_kmip_client_certificate(
            adapter_id=self.__class__.kmip_name,
            id=self.__class__.kmip_cert_name,
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_kmip_adapter(self):
        response = self.ibm_key_protect_api_service.delete_kmip_adapter(
            id=self.__class__.kmip_name,
            bluemix_instance=self.__class__.bluemix_instance,
        )

        assert response.get_status_code() == 204

    @pytest.mark.skip(
        reason="Skipping test_delete_kmip_object"
    )  # MANUAL: Added skip decorator
    @needscredentials
    def test_delete_kmip_object(self):
        object_id = self.__class__.kmip_object
        if object_id is None:
            pytest.skip("No KMIP object available")

        response = self.ibm_key_protect_api_service.delete_kmip_object(
            adapter_id=self.__class__.kmip_name,
            bluemix_instance=self.__class__.bluemix_instance,
            id=self.__class__.kmip_object,
            force=False,
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_cleanup_resources(self):
        # MANUAL: Added comprehensive cleanup test with error handling
        print("\nCleaning up resources...\n")

        if self.__class__.created_key_id:
            try:
                print(f"Deleting created key: {self.__class__.created_key_id}")
                self.ibm_key_protect_api_service.delete_key(
                    id=self.__class__.created_key_id,
                    bluemix_instance=self.__class__.bluemix_instance,
                    prefer="return=representation",
                )
            except Exception as e:
                print(f"Failed deleting created key: {e}")

            try:
                print(f"Purging created key: {self.__class__.created_key_id}")
                self.ibm_key_protect_api_service.purge_key(
                    id=self.__class__.created_key_id,
                    bluemix_instance=self.__class__.bluemix_instance,
                    prefer="return=representation",
                )
            except Exception as e:
                print(f"Failed purging created key: {e}")

        if self.__class__.policies_overriden_key_id:
            try:
                print(
                    f"Deleting policies overridden key: {self.__class__.policies_overriden_key_id}"
                )
                self.ibm_key_protect_api_service.delete_key(
                    id=self.__class__.policies_overriden_key_id,
                    bluemix_instance=self.__class__.bluemix_instance,
                    prefer="return=representation",
                    force=False,
                )
            except Exception as e:
                print(f"Failed deleting policies overridden key: {e}")

            try:
                print(
                    f"Purging policies overridden key: {self.__class__.policies_overriden_key_id}"
                )
                self.ibm_key_protect_api_service.purge_key(
                    id=self.__class__.policies_overriden_key_id,
                    bluemix_instance=self.__class__.bluemix_instance,
                    prefer="return=representation",
                )
            except Exception as e:
                print(f"Failed purging policies overridden key: {e}")

        if self.__class__.created_keyring_id:
            try:
                print(f"Deleting key ring: {self.__class__.created_keyring_id}")
                self.ibm_key_protect_api_service.delete_key_ring(
                    key_ring_id=self.__class__.created_keyring_id,
                    bluemix_instance=self.__class__.bluemix_instance,
                    force=False,
                )
            except Exception as e:
                print(f"Failed deleting key ring: {e}")

