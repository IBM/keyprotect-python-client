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
Examples for IbmKeyProtectApiV2
"""

from ibm_cloud_sdk_core import ApiException, read_external_sources
import io
import os
import pytest
import json
import time
from datetime import datetime, timezone, timedelta
from keyprotect.ibm_key_protect_api_v2 import *
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa

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
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

#
# This file provides an example of how to use the IBM Key Protect API service.
#
# The following configuration properties are assumed to be defined:
# IBM_KEY_PROTECT_API_URL=<service base url>
# IBM_KEY_PROTECT_API_AUTH_TYPE=iam
# IBM_KEY_PROTECT_API_APIKEY=<IAM apikey>
# IBM_KEY_PROTECT_API_AUTH_URL=<IAM token service base URL - omit this if using the production environment>
#
# These configuration properties can be exported as environment variables, or stored
# in a configuration file and then:
# export IBM_CREDENTIALS_FILE=<name of configuration file>
#
config_file = 'ibm_key_protect_api_v2.env'

ibm_key_protect_api_service = None

config = None


##############################################################################
# Start of Examples for Service: IbmKeyProtectApiV2
##############################################################################
# region
class TestIbmKeyProtectApiV2Examples:
    """
    Example Test Class for IbmKeyProtectApiV2
    """

    @classmethod
    def setup_class(cls):
        global ibm_key_protect_api_service
        if os.path.exists(config_file):
            os.environ['IBM_CREDENTIALS_FILE'] = config_file

            ibm_key_protect_api_service = IbmKeyProtectApiV2.new_instance(
            )

            assert ibm_key_protect_api_service is not None

            # Load the configuration
            global config
            config = read_external_sources(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME)
            
            # Initialize class variables for test state management
            cls.created_keyring_id = "test-example-keyring"
            cls.kmip_name = "test-example-kmip"
            cls.kmip_cert_name = "Test-example-certificate"
            cls.bluemix_instance = config.get("BLUEMIX_INSTANCE")
            cls.created_key_id = None
            cls.policies_overriden_key_id = None
            cls.ciphertext = None
            cls.disable_key_timestamp = None
            cls.delete_key_timestamp = None

        print('Setup complete.')

    needscredentials = pytest.mark.skipif(
        not os.path.exists(config_file), reason="External configuration not available, skipping..."
    )

    @needscredentials
    def test_get_key_collection_metadata_example(self):
        """
        get_key_collection_metadata request example
        """
        try:
            # begin-getKeyCollectionMetadata

            response = ibm_key_protect_api_service.get_key_collection_metadata(
                bluemix_instance=self.__class__.bluemix_instance,
                state=[0, 1, 2, 3],
                extractable=True,
            )

            # end-getKeyCollectionMetadata
            print('\nget_key_collection_metadata() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_create_key_example(self):
        """
        create_key request example
        """
        try:
            print('\ncreate_key() result:')

            # begin-createKey

            key_create_body = {
                "metadata": {
                    "collectionType": "application/vnd.ibm.kms.key+json",
                    "collectionTotal": 1,
                },
                "resources": [
                    {
                        "type": "application/vnd.ibm.kms.key+json",
                        "name": "example-created-test-root-key",
                        "description": "A Key Protect key used for integration testing",
                        "extractable": False,
                    }
                ],
            }

            response = ibm_key_protect_api_service.create_key(
                bluemix_instance=self.__class__.bluemix_instance,
                key_create_body=io.BytesIO(json.dumps(key_create_body).encode("utf-8")),
                prefer="return=representation",
            )
            key = response.get_result()
            key_data = key.json()
            key_id = key_data["resources"][0]["id"]
            
            # Store the key ID in class variable for use in other tests
            self.__class__.created_key_id = key_id

            print(key_data)

            # end-createKey

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_keys_example(self):
        """
        get_keys request example
        """
        try:
            print('\nget_keys() result:')

            # begin-getKeys

            response = ibm_key_protect_api_service.get_keys(
                bluemix_instance=self.__class__.bluemix_instance,
            )
            list_keys = response.get_result()

            print(list_keys)

            # end-getKeys

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_create_key_with_policies_overrides_example(self):
        """
        create_key_with_policies_overrides request example
        """
        try:
            print('\ncreate_key_with_policies_overrides() result:')

            # begin-createKeyWithPoliciesOverrides

            key_with_policy_overrides_create_body = {
                "metadata": {
                    "collectionType": "application/vnd.ibm.kms.key+json",
                    "collectionTotal": 1,
                },
                "resources": [
                    {
                        "type": "application/vnd.ibm.kms.key+json",
                        "name": "example-policies-test-overriden-key",
                        "description": "A Key Protect key used for integration testing",
                        "extractable": False,
                        "dualAuthDelete": {"enabled": False},
                        "rotation": {"enabled": True, "interval_month": 6},
                    }
                ],
            }

            response = ibm_key_protect_api_service.create_key_with_policies_overrides(
                bluemix_instance=self.__class__.bluemix_instance,
                key_with_policy_overrides_create_body=io.BytesIO(
                    json.dumps(key_with_policy_overrides_create_body).encode("utf-8")
                ),
                prefer="return=representation",
            )
            key = response.get_result()
            key_data = key.json()
            key_id = key_data["resources"][0]["id"]
            
            # Store the key ID in class variable for use in other tests
            self.__class__.policies_overriden_key_id = key_id

            print(key_data)

            # end-createKeyWithPoliciesOverrides

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_key_example(self):
        """
        get_key request example
        """
        try:
            print('\nget_key() result:')

            # begin-getKey

            response = ibm_key_protect_api_service.get_key(
                id=self.__class__.created_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
            )
            get_key = response.get_result()

            print(get_key)

            # end-getKey

        except ApiException as e:
            pytest.fail(str(e))

    @pytest.mark.skip(
        reason="Skipping because key with dual authorization can't be accessed using one call through integration tests"
    )
    @needscredentials
    def test_set_key_for_deletion_example(self):
        """
        set_key_for_deletion request example
        """
        try:
            # begin-setKeyForDeletion

            response = ibm_key_protect_api_service.set_key_for_deletion(
                id=self.__class__.policies_overriden_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
            )

            # end-setKeyForDeletion
            print('\nset_key_for_deletion() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))

    @pytest.mark.skip(
        reason="Skipping because key with dual authorization can't be accessed using one call through integration tests"
    )
    @needscredentials
    def test_unset_key_for_deletion_example(self):
        """
        unset_key_for_deletion request example
        """
        try:
            # begin-unsetKeyForDeletion

            response = ibm_key_protect_api_service.unset_key_for_deletion(
                id=self.__class__.policies_overriden_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
            )

            # end-unsetKeyForDeletion
            print('\nunset_key_for_deletion() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_key_metadata_example(self):
        """
        get_key_metadata request example
        """
        try:
            print('\nget_key_metadata() result:')

            # begin-getKeyMetadata

            response = ibm_key_protect_api_service.get_key_metadata(
                id=self.__class__.created_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
            )
            get_key_metadata = response.get_result()

            print(get_key_metadata)

            # end-getKeyMetadata

        except ApiException as e:
            pytest.fail(str(e))


    @needscredentials
    def test_get_key_versions_example(self):
        """
        get_key_versions request example
        """
        try:
            print('\nget_key_versions() result:')

            # begin-getKeyVersions

            response = ibm_key_protect_api_service.get_key_versions(
                id=self.__class__.created_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
            )
            list_key_versions = response.get_result()

            print(list_key_versions)

            # end-getKeyVersions

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_wrap_key_example(self):
        """
        wrap_key request example
        """
        try:
            print('\nwrap_key() result:')

            # begin-wrapKey

            key_action_wrap_body = {
                "plaintext": "cGxhaW50ZXh0LWRhdGEta2V5",
            }

            response = ibm_key_protect_api_service.wrap_key(
                id=self.__class__.created_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
                key_action_wrap_body=io.BytesIO(
                    json.dumps(key_action_wrap_body).encode("utf-8")
                ),
            )
            wrap_key_response_body = response.get_result()
            wrap_key_response_data = wrap_key_response_body.json()
            ciphertext = wrap_key_response_data["ciphertext"]
            
            # Store ciphertext for use in unwrap/rewrap tests
            self.__class__.ciphertext = ciphertext

            print(wrap_key_response_body)

            # end-wrapKey

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_unwrap_key_example(self):
        """
        unwrap_key request example
        """
        try:
            print('\nunwrap_key() result:')

            # begin-unwrapKey

            key_action_unwrap_body = {
                "ciphertext": self.__class__.ciphertext,
            }

            response = ibm_key_protect_api_service.unwrap_key(
                id=self.__class__.created_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
                key_action_unwrap_body=io.BytesIO(
                    json.dumps(key_action_unwrap_body).encode("utf-8")
                ),
            )
            unwrap_key_response_body = response.get_result()

            print(unwrap_key_response_body)

            # end-unwrapKey

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_rewrap_key_example(self):
        """
        rewrap_key request example
        """
        try:
            print('\nrewrap_key() result:')

            # begin-rewrapKey

            key_action_rewrap_body = {
                "ciphertext": self.__class__.ciphertext,
            }

            response = ibm_key_protect_api_service.rewrap_key(
                id=self.__class__.created_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
                key_action_rewrap_body=io.BytesIO(
                    json.dumps(key_action_rewrap_body).encode("utf-8")
                ),
            )
            rewrap_key_response_body = response.get_result()

            print(rewrap_key_response_body)

            # end-rewrapKey

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_rotate_key_example(self):
        """
        rotate_key request example
        """
        try:
            print('\nrotate_key() result:')

            # begin-rotateKey

            key_action_rotate_body = {}

            response = ibm_key_protect_api_service.rotate_key(
                id=self.__class__.created_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
                key_action_rotate_body=io.BytesIO(
                    json.dumps(key_action_rotate_body).encode("utf-8")
                ),
                prefer="return=representation",
            )

            # end-rotateKey
            print('\nrotate_key() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))
            
    @needscredentials
    def test_disable_key_example(self):
        """
        disable_key request example
        """
        try:
            # begin-disableKey

            response = ibm_key_protect_api_service.disable_key(
                id=self.__class__.created_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
            )

            # end-disableKey
            print('\ndisable_key() response status code: ', response.get_status_code())
            # Record timestamp for rate limit handling in test_enable_key
            self.__class__.disable_key_timestamp = time.time()

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_enable_key_example(self):
        """
        enable_key request example
        """
        try:
            # Wait 31 seconds after disable to respect API rate limits
            if self.__class__.disable_key_timestamp is not None:
                elapsed = time.time() - self.__class__.disable_key_timestamp
                if elapsed < 31:
                    time.sleep(31 - elapsed)

            # begin-enableKey

            response = ibm_key_protect_api_service.enable_key(
                id=self.__class__.created_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
            )

            # end-enableKey
            print('\nenable_key() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_put_policy_example(self):
        """
        put_policy request example
        """
        try:
            print('\nput_policy() result:')

            # begin-putPolicy

            collection_metadata_model = {
                'collectionType': 'application/vnd.ibm.kms.policy+json',
                'collectionTotal': 1,
            }

            key_policy_dual_auth_delete_dual_auth_delete_model = {
                'enabled': False,
            }

            key_policy_dual_auth_delete_model = {
                'type': 'application/vnd.ibm.kms.policy+json',
                'dualAuthDelete': key_policy_dual_auth_delete_dual_auth_delete_model,
            }

            set_key_policies_one_of_model = {
                'metadata': collection_metadata_model,
                'resources': [key_policy_dual_auth_delete_model],
            }

            response = ibm_key_protect_api_service.put_policy(
                id=self.__class__.policies_overriden_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
                key_policy_put_body=set_key_policies_one_of_model,
                policy='dualAuthDelete',
            )
            get_key_policies_one_of = response.get_result()

            print(get_key_policies_one_of)

            # end-putPolicy

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_policy_example(self):
        """
        get_policy request example
        """
        try:
            print('\nget_policy() result:')

            # begin-getPolicy

            response = ibm_key_protect_api_service.get_policy(
                id=self.__class__.policies_overriden_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
                policy='dualAuthDelete',
            )
            get_key_policies_one_of = response.get_result()

            print(get_key_policies_one_of)

            # end-getPolicy

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_put_instance_policy_example(self):
        """
        put_instance_policy request example
        """
        try:
            # begin-putInstancePolicy

            collection_metadata_model = {
                'collectionType': 'application/vnd.ibm.kms.policy+json',
                'collectionTotal': 1,
            }

            instance_policy_allowed_network_policy_data_attributes_model = {
                'allowed_network': 'public-and-private',
            }

            instance_policy_allowed_network_policy_data_model = {
                'enabled': True,
                'attributes': instance_policy_allowed_network_policy_data_attributes_model,
            }

            set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model = {
                'policy_type': 'allowedNetwork',
                'policy_data': instance_policy_allowed_network_policy_data_model,
            }

            set_instance_policies_one_of_model = {
                'metadata': collection_metadata_model,
                'resources': [set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model],
            }

            response = ibm_key_protect_api_service.put_instance_policy(
                bluemix_instance=self.__class__.bluemix_instance,
                instance_policy_put_body=set_instance_policies_one_of_model,
                policy='allowedNetwork',
            )

            # end-putInstancePolicy
            print('\nput_instance_policy() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_instance_policy_example(self):
        """
        get_instance_policy request example
        """
        try:
            print('\nget_instance_policy() result:')

            # begin-getInstancePolicy

            response = ibm_key_protect_api_service.get_instance_policy(
                bluemix_instance=self.__class__.bluemix_instance,
            )
            get_instance_policies_one_of = response.get_result()

            print(get_instance_policies_one_of)

            # end-getInstancePolicy

        except ApiException as e:
            pytest.fail(str(e))

    @pytest.mark.skip(
        reason="Skipping because the instance has to be public to test api calls using integration tests"
    )
    @needscredentials
    def test_get_allowed_ip_port_example(self):
        """
        get_allowed_ip_port request example
        """
        try:
            print('\nget_allowed_ip_port() result:')

            # begin-getAllowedIPPort

            response = ibm_key_protect_api_service.get_allowed_ip_port(
                bluemix_instance=self.__class__.bluemix_instance,
            )
            allowed_ip_port = response.get_result()

            print(allowed_ip_port)

            # end-getAllowedIPPort

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_post_import_token_example(self):
        """
        post_import_token request example
        """
        try:
            print('\npost_import_token() result:')

            # begin-postImportToken

            response = ibm_key_protect_api_service.post_import_token(
                bluemix_instance=self.__class__.bluemix_instance,
            )
            import_token = response.get_result()

            print(import_token)

            # end-postImportToken

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_import_token_example(self):
        """
        get_import_token request example
        """
        try:
            print('\nget_import_token() result:')

            # begin-getImportToken

            response = ibm_key_protect_api_service.get_import_token(
                bluemix_instance=self.__class__.bluemix_instance,
            )
            get_import_token = response.get_result()

            print(get_import_token)

            # end-getImportToken

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_registrations_example(self):
        """
        get_registrations request example
        """
        try:
            print('\nget_registrations() result:')

            # begin-getRegistrations

            response = ibm_key_protect_api_service.get_registrations(
                id=self.__class__.created_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
            )
            registration_with_total_count = response.get_result()

            print(registration_with_total_count)

            # end-getRegistrations

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_registrations_all_keys_example(self):
        """
        get_registrations_all_keys request example
        """
        try:
            print('\nget_registrations_all_keys() result:')

            # begin-getRegistrationsAllKeys

            response = ibm_key_protect_api_service.get_registrations_all_keys(
                bluemix_instance=self.__class__.bluemix_instance,
            )
            registration_with_total_count = response.get_result()

            print(registration_with_total_count)

            # end-getRegistrationsAllKeys

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_create_key_alias_example(self):
        """
        create_key_alias request example
        """
        try:
            print('\ncreate_key_alias() result:')

            # begin-createKeyAlias

            response = ibm_key_protect_api_service.create_key_alias(
                id=self.__class__.created_key_id,
                alias='testString',
                bluemix_instance=self.__class__.bluemix_instance,
            )
            key_alias = response.get_result()

            print(key_alias)

            # end-createKeyAlias

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_delete_key_alias_example(self):
        """
        delete_key_alias request example
        """
        try:
            # begin-deleteKeyAlias

            response = ibm_key_protect_api_service.delete_key_alias(
                id=self.__class__.created_key_id,
                alias='testString',
                bluemix_instance=self.__class__.bluemix_instance,
            )

            # end-deleteKeyAlias
            print('\ndelete_key_alias() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_list_key_rings_example(self):
        """
        list_key_rings request example
        """
        try:
            print('\nlist_key_rings() result:')

            # begin-listKeyRings

            response = ibm_key_protect_api_service.list_key_rings(
                bluemix_instance=self.__class__.bluemix_instance,
            )

            # end-listKeyRings
            list_key_rings_with_total_count = response.get_result()

            print(list_key_rings_with_total_count)


        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_kmip_adapters_example(self):
        """
        get_kmip_adapters request example
        """
        try:
            print('\nget_kmip_adapters() result:')

            # begin-get_kmip_adapters

            response = ibm_key_protect_api_service.get_kmip_adapters(
                bluemix_instance=self.__class__.bluemix_instance,
                crk_id='feddecaf-0000-0000-0000-1234567890ab',
            )
            list_kmip_adapters_with_total_count = response.get_result()

            print(list_kmip_adapters_with_total_count)

            # end-get_kmip_adapters

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_create_key_ring_example(self):
        """
        create_key_ring request example
        """
        try:
            # begin-createKeyRing

            response = ibm_key_protect_api_service.create_key_ring(
                key_ring_id=self.__class__.created_keyring_id,
                bluemix_instance=self.__class__.bluemix_instance,
            )

            # end-createKeyRing
            print('\ncreate_key_ring() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_patch_key_example(self):
        """
        patch_key request example
        """
        try:
            print('\npatch_key() result:')

            # begin-patchKey

            key_patch_body = {"keyRingID": self.__class__.created_keyring_id}

            response = ibm_key_protect_api_service.patch_key(
                id=self.__class__.created_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
                key_patch_body=io.BytesIO(json.dumps(key_patch_body).encode("utf-8")),
            )
            patch_key_response_body = response.get_result()

            print(patch_key_response_body)

            # end-patchKey

        except ApiException as e:
            pytest.fail(str(e))

    @pytest.mark.skip(
        reason="Skipping because after a key is deleted, there is a wait period of up to four hours before purge key operation is allowed"
    )
    @needscredentials
    def test_purge_key_example(self):
        """
        purge_key request example
        """
        try:
            print('\npurge_key() result:')

            # begin-purgeKey

            response = ibm_key_protect_api_service.purge_key(
                id=self.__class__.created_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
                x_kms_key_ring=self.__class__.created_keyring_id,
                prefer="return=representation",
            )
            purge_key = response.get_result()

            print(purge_key)

            # end-purgeKey

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_delete_key_example(self):
        """
        delete_key request example
        """
        try:
            print('\ndelete_key() result:')

            # begin-deleteKey

            response = ibm_key_protect_api_service.delete_key(
                id=self.__class__.created_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
                x_kms_key_ring=self.__class__.created_keyring_id,
            )
            delete_key = response.get_result()

            print(delete_key)

            # end-deleteKey

            # Record timestamp for rate limit handling in test_restore_key
            self.__class__.delete_key_timestamp = time.time()


        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_restore_key_example(self):
        """
        restore_key request example
        """
        try:
            print('\nrestore_key() result:')

            # Wait 31 seconds after delete to respect API rate limits
            if self.__class__.delete_key_timestamp is not None:
                elapsed = time.time() - self.__class__.delete_key_timestamp
                if elapsed < 31:
                    time.sleep(31 - elapsed)

            # begin-restoreKey

            response = ibm_key_protect_api_service.restore_key(
                id=self.__class__.created_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
                x_kms_key_ring=self.__class__.created_keyring_id,
                prefer="return=representation",
            )
            result = response.get_result()

            # end-restoreKey

            # with open('/tmp/result.out', 'wb') as fp:
            #     fp.write(result)


        except ApiException as e:
            pytest.fail(str(e))


    @needscredentials
    def test_create_kmip_adapter_example(self):
        """
        create_kmip_adapter request example
        """
        try:
            print('\ncreate_kmip_adapter() result:')

            # begin-create_kmip_adapter

            # MANUALLY: Use model format
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

            response = ibm_key_protect_api_service.create_kmip_adapter(
                bluemix_instance=self.__class__.bluemix_instance,
                metadata=collection_metadata_model,
                resources=[create_kmip_adapter_object_model],
            )
            list_kmip_adapters = response.get_result()

            print(list_kmip_adapters)

            # end-create_kmip_adapter

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_kmip_adapter_example(self):
        """
        get_kmip_adapter request example
        """
        try:
            print('\nget_kmip_adapter() result:')

            # begin-get_kmip_adapter

            response = ibm_key_protect_api_service.get_kmip_adapter(
                id=self.__class__.kmip_name,
                bluemix_instance=self.__class__.bluemix_instance,
            )
            list_kmip_adapters = response.get_result()

            print(list_kmip_adapters)

            # end-get_kmip_adapter

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_kmip_objects_example(self):
        """
        get_kmip_objects request example
        """
        try:
            print('\nget_kmip_objects() result:')

            # begin-get_kmip_objects

            response = ibm_key_protect_api_service.get_kmip_objects(
                adapter_id=self.__class__.kmip_name,
                bluemix_instance=self.__class__.bluemix_instance,
            )
            list_kmip_objects_with_total_count = response.get_result()

            print(list_kmip_objects_with_total_count)

            # end-get_kmip_objects

        except ApiException as e:
            pytest.fail(str(e))

    @pytest.mark.skip(
        reason="Skipping because cannot create kmip object using API call so can't call get on an object that doesn't exist in integration test environment"
    )
    @needscredentials
    def test_get_kmip_object_example(self):
        """
        get_kmip_object request example
        """
        try:
            print('\nget_kmip_object() result:')

            # begin-get_kmip_object

            response = ibm_key_protect_api_service.get_kmip_object(
                adapter_id=self.__class__.kmip_name,
                bluemix_instance=self.__class__.bluemix_instance,
                id='testString',
            )
            list_kmip_objects_with_total_count = response.get_result()

            print(list_kmip_objects_with_total_count)

            # end-get_kmip_object

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_kmip_client_certificates_example(self):
        """
        get_kmip_client_certificates request example
        """
        try:
            print('\nget_kmip_client_certificates() result:')

            # begin-get_kmip_client_certificates

            response = ibm_key_protect_api_service.get_kmip_client_certificates(
                adapter_id=self.__class__.kmip_name,
                bluemix_instance=self.__class__.bluemix_instance,
            )
            list_kmip_partial_client_certificates_with_total_count = response.get_result()

            print(list_kmip_partial_client_certificates_with_total_count)

            # end-get_kmip_client_certificates

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_add_kmip_client_certificate_example(self):
        """
        add_kmip_client_certificate request example
        """
        try:
            print('\nadd_kmip_client_certificate() result:')

            # begin-add_kmip_client_certificate

            collection_metadata_model = {
                'collectionType': 'application/vnd.ibm.kms.kmip_client_certificate+json',
                'collectionTotal': 1,
            }

            # MANUAL: Generate certificate in memory instead of reading from temp.pem
            certificate = generate_test_cert_pem()

            create_kmip_client_certificate_object_model = {
                'certificate': certificate,
                'name': self.__class__.kmip_cert_name,
            }

            response = ibm_key_protect_api_service.add_kmip_client_certificate(
                adapter_id=self.__class__.kmip_name,
                bluemix_instance=self.__class__.bluemix_instance,
                metadata=collection_metadata_model,
                resources=[create_kmip_client_certificate_object_model],
            )
            list_kmip_client_certificates = response.get_result()

            print(list_kmip_client_certificates)

            # end-add_kmip_client_certificate

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_kmip_client_certificate_example(self):
        """
        get_kmip_client_certificate request example
        """
        try:
            print('\nget_kmip_client_certificate() result:')

            # begin-get_kmip_client_certificate

            response = ibm_key_protect_api_service.get_kmip_client_certificate(
                adapter_id=self.__class__.kmip_name,
                id=self.__class__.kmip_cert_name,
                bluemix_instance=self.__class__.bluemix_instance,
            )
            list_kmip_client_certificates = response.get_result()

            print(list_kmip_client_certificates)

            # end-get_kmip_client_certificate

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_delete_key_ring_example(self):
        """
        delete_key_ring request example
        """
        try:
            # begin-deleteKeyRing

            # Move key to default ring before deleting keyring
            key_patch_body = {"keyRingID": "default"}

            response = ibm_key_protect_api_service.patch_key(
                id=self.__class__.created_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
                x_kms_key_ring=self.__class__.created_keyring_id,
                key_patch_body=io.BytesIO(json.dumps(key_patch_body).encode("utf-8")),
            )

            response = ibm_key_protect_api_service.delete_key_ring(
                key_ring_id=self.__class__.created_keyring_id,
                bluemix_instance=self.__class__.bluemix_instance,
            )

            # end-deleteKeyRing
            print('\ndelete_key_ring() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))


    @needscredentials
    def test_sync_associated_resources_example(self):
        """
        sync_associated_resources request example
        """
        try:
            # begin-syncAssociatedResources

            response = ibm_key_protect_api_service.sync_associated_resources(
                id=self.__class__.policies_overriden_key_id,
                bluemix_instance=self.__class__.bluemix_instance,
            )

            # end-syncAssociatedResources
            print('\nsync_associated_resources() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))

    @pytest.mark.skip(
        reason="Skipping because cannot delete kmip object using API call so can't call delete on an object that doesn't exist in integration test environment"
    )
    @needscredentials
    def test_delete_kmip_object_example(self):
        """
        delete_kmip_object request example
        """
        try:
            # begin-delete_kmip_object

            response = ibm_key_protect_api_service.delete_kmip_object(
                adapter_id=self.__class__.kmip_name,
                bluemix_instance=self.__class__.bluemix_instance,
                id='testString',
            )

            # end-delete_kmip_object
            print('\ndelete_kmip_object() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_delete_kmip_client_certificate_example(self):
        """
        delete_kmip_client_certificate request example
        """
        try:

            # begin-delete_kmip_object

            response = ibm_key_protect_api_service.delete_kmip_client_certificate(
                adapter_id=self.__class__.kmip_name,
                id=self.__class__.kmip_cert_name,
                bluemix_instance=self.__class__.bluemix_instance,
            )

            # end-delete_kmip_object

            print('\ndelete_kmip_client_certificate() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(reason=str(e))

    @needscredentials
    def test_delete_kmip_adapter_example(self):
        """
        delete_kmip_adapter request example
        """
        try:

            # begin-delete_kmip_adapter

            response = ibm_key_protect_api_service.delete_kmip_adapter(
                id=self.__class__.kmip_name,
                bluemix_instance=self.__class__.bluemix_instance,
            )
            
            # end-delete_kmip_adapter

            print('\ndelete_kmip_adapter() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))
            
    @needscredentials
    def test_cleanup_resources(self):
        """
        Cleanup test resources
        """
        print("\nCleaning up resources...\n")

        if self.__class__.created_key_id:
            try:
                print(f"Deleting created key: {self.__class__.created_key_id}")
                ibm_key_protect_api_service.delete_key(
                    id=self.__class__.created_key_id,
                    bluemix_instance=self.__class__.bluemix_instance,
                    prefer="return=representation",
                )
            except Exception as e:
                print(f"Failed deleting created key: {e}")

            try:
                print(f"Purging created key: {self.__class__.created_key_id}")
                ibm_key_protect_api_service.purge_key(
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
                ibm_key_protect_api_service.delete_key(
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
                ibm_key_protect_api_service.purge_key(
                    id=self.__class__.policies_overriden_key_id,
                    bluemix_instance=self.__class__.bluemix_instance,
                    prefer="return=representation",
                )
            except Exception as e:
                print(f"Failed purging policies overridden key: {e}")

        if self.__class__.created_keyring_id:
            try:
                print(f"Deleting key ring: {self.__class__.created_keyring_id}")
                ibm_key_protect_api_service.delete_key_ring(
                    key_ring_id=self.__class__.created_keyring_id,
                    bluemix_instance=self.__class__.bluemix_instance,
                    force=False,
                )
            except Exception as e:
                print(f"Failed deleting key ring: {e}")


# endregion
##############################################################################
# End of Examples for Service: IbmKeyProtectApiV2
##############################################################################
