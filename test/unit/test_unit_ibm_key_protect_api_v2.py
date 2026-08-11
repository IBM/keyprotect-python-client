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
Unit Tests for IbmKeyProtectApiV2
"""

from datetime import datetime, timezone
from ibm_cloud_sdk_core.authenticators.no_auth_authenticator import NoAuthAuthenticator
from ibm_cloud_sdk_core.utils import datetime_to_string, string_to_datetime
import base64
import inspect
import io
import json
import os
import pytest
import re
import requests
import responses
import tempfile
import urllib
from keyprotect.ibm_key_protect_api_v2 import *

_service = IbmKeyProtectApiV2(authenticator=NoAuthAuthenticator())

_base_url = "https://us-south.kms.cloud.ibm.com"
_service.set_service_url(_base_url)


def preprocess_url(operation_path: str):
    """
    Returns the request url associated with the specified operation path.
    This will be base_url concatenated with a quoted version of operation_path.
    The returned request URL is used to register the mock response so it needs
    to match the request URL that is formed by the requests library.
    """

    # Form the request URL from the base URL and operation path.
    request_url = _base_url + operation_path

    # If the request url does NOT end with a /, then just return it as-is.
    # Otherwise, return a regular expression that matches one or more trailing /.
    if not request_url.endswith("/"):
        return request_url
    return re.compile(request_url.rstrip("/") + "/+")


def test_parameterized_url():
    """
    Test formatting the parameterized service URL with the default variable values.
    """
    default_formatted_url = "https://us-south.kms.cloud.ibm.com"
    assert IbmKeyProtectApiV2.construct_service_url() == default_formatted_url


##############################################################################
# Start of Service: Keys
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ["TEST_SERVICE_AUTH_TYPE"] = "noAuth"

        service = IbmKeyProtectApiV2.new_instance(
            service_name="TEST_SERVICE",
        )

        assert service is not None
        assert isinstance(service, IbmKeyProtectApiV2)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match="authenticator must be provided"):
            service = IbmKeyProtectApiV2.new_instance(
                service_name="TEST_SERVICE_NOT_FOUND",
            )


class TestGetKeyCollectionMetadata:
    """
    Test Class for get_key_collection_metadata
    """

    @responses.activate
    def test_get_key_collection_metadata_all_params(self):
        """
        get_key_collection_metadata()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys")
        responses.add(
            responses.HEAD,
            url,
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"
        correlation_id = "testString"
        state = [0, 1, 2, 3]
        extractable = True
        filter = "testString"
        x_kms_key_ring = "testString"

        # Invoke method
        response = _service.get_key_collection_metadata(
            bluemix_instance,
            correlation_id=correlation_id,
            state=state,
            extractable=extractable,
            filter=filter,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "state={}".format(",".join([str(x) for x in state])) in query_string
        assert "extractable={}".format("true" if extractable else "false") in query_string
        assert "filter={}".format(filter) in query_string

    def test_get_key_collection_metadata_all_params_with_retries(self):
        # Enable retries and run test_get_key_collection_metadata_all_params.
        _service.enable_retries()
        self.test_get_key_collection_metadata_all_params()

        # Disable retries and run test_get_key_collection_metadata_all_params.
        _service.disable_retries()
        self.test_get_key_collection_metadata_all_params()

    @responses.activate
    def test_get_key_collection_metadata_required_params(self):
        """
        test_get_key_collection_metadata_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys")
        responses.add(
            responses.HEAD,
            url,
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_key_collection_metadata(
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_key_collection_metadata_required_params_with_retries(self):
        # Enable retries and run test_get_key_collection_metadata_required_params.
        _service.enable_retries()
        self.test_get_key_collection_metadata_required_params()

        # Disable retries and run test_get_key_collection_metadata_required_params.
        _service.disable_retries()
        self.test_get_key_collection_metadata_required_params()

    @responses.activate
    def test_get_key_collection_metadata_value_error(self):
        """
        test_get_key_collection_metadata_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys")
        responses.add(
            responses.HEAD,
            url,
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_key_collection_metadata(**req_copy)

    def test_get_key_collection_metadata_value_error_with_retries(self):
        # Enable retries and run test_get_key_collection_metadata_value_error.
        _service.enable_retries()
        self.test_get_key_collection_metadata_value_error()

        # Disable retries and run test_get_key_collection_metadata_value_error.
        _service.disable_retries()
        self.test_get_key_collection_metadata_value_error()


class TestCreateKey:
    """
    Test Class for create_key
    """

    @responses.activate
    def test_create_key_all_params(self):
        """
        create_key()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=201,
        )

        # Set up parameter values
        bluemix_instance = "testString"
        key_create_body = io.BytesIO(b"This is a mock file.").getvalue()
        correlation_id = "testString"
        prefer = "return=representation"
        x_kms_key_ring = "default"

        # Invoke method
        response = _service.create_key(
            bluemix_instance,
            key_create_body,
            correlation_id=correlation_id,
            prefer=prefer,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        assert responses.calls[0].request.body == key_create_body

    def test_create_key_all_params_with_retries(self):
        # Enable retries and run test_create_key_all_params.
        _service.enable_retries()
        self.test_create_key_all_params()

        # Disable retries and run test_create_key_all_params.
        _service.disable_retries()
        self.test_create_key_all_params()

    @responses.activate
    def test_create_key_required_params(self):
        """
        test_create_key_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=201,
        )

        # Set up parameter values
        bluemix_instance = "testString"
        key_create_body = io.BytesIO(b"This is a mock file.").getvalue()

        # Invoke method
        response = _service.create_key(
            bluemix_instance,
            key_create_body,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        assert responses.calls[0].request.body == key_create_body

    def test_create_key_required_params_with_retries(self):
        # Enable retries and run test_create_key_required_params.
        _service.enable_retries()
        self.test_create_key_required_params()

        # Disable retries and run test_create_key_required_params.
        _service.disable_retries()
        self.test_create_key_required_params()

    @responses.activate
    def test_create_key_value_error(self):
        """
        test_create_key_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=201,
        )

        # Set up parameter values
        bluemix_instance = "testString"
        key_create_body = io.BytesIO(b"This is a mock file.").getvalue()

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bluemix_instance": bluemix_instance,
            "key_create_body": key_create_body,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_key(**req_copy)

    def test_create_key_value_error_with_retries(self):
        # Enable retries and run test_create_key_value_error.
        _service.enable_retries()
        self.test_create_key_value_error()

        # Disable retries and run test_create_key_value_error.
        _service.disable_retries()
        self.test_create_key_value_error()


class TestGetKeys:
    """
    Test Class for get_keys
    """

    @responses.activate
    def test_get_keys_all_params(self):
        """
        get_keys()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "incompleteSearch": false, "searchQuery": {"query": "query", "scopes": ["name"], "not": true, "exact": false}}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"
        correlation_id = "testString"
        limit = 200
        offset = 0
        state = [0, 1, 2, 3]
        extractable = True
        search = "testString"
        sort = "id"
        filter = "testString"
        x_kms_key_ring = "testString"

        # Invoke method
        response = _service.get_keys(
            bluemix_instance,
            correlation_id=correlation_id,
            limit=limit,
            offset=offset,
            state=state,
            extractable=extractable,
            search=search,
            sort=sort,
            filter=filter,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "limit={}".format(limit) in query_string
        assert "offset={}".format(offset) in query_string
        assert "state={}".format(",".join([str(x) for x in state])) in query_string
        assert "extractable={}".format("true" if extractable else "false") in query_string
        assert "search={}".format(search) in query_string
        assert "sort={}".format(sort) in query_string
        assert "filter={}".format(filter) in query_string

    def test_get_keys_all_params_with_retries(self):
        # Enable retries and run test_get_keys_all_params.
        _service.enable_retries()
        self.test_get_keys_all_params()

        # Disable retries and run test_get_keys_all_params.
        _service.disable_retries()
        self.test_get_keys_all_params()

    @responses.activate
    def test_get_keys_required_params(self):
        """
        test_get_keys_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "incompleteSearch": false, "searchQuery": {"query": "query", "scopes": ["name"], "not": true, "exact": false}}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_keys(
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_keys_required_params_with_retries(self):
        # Enable retries and run test_get_keys_required_params.
        _service.enable_retries()
        self.test_get_keys_required_params()

        # Disable retries and run test_get_keys_required_params.
        _service.disable_retries()
        self.test_get_keys_required_params()

    @responses.activate
    def test_get_keys_value_error(self):
        """
        test_get_keys_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "incompleteSearch": false, "searchQuery": {"query": "query", "scopes": ["name"], "not": true, "exact": false}}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_keys(**req_copy)

    def test_get_keys_value_error_with_retries(self):
        # Enable retries and run test_get_keys_value_error.
        _service.enable_retries()
        self.test_get_keys_value_error()

        # Disable retries and run test_get_keys_value_error.
        _service.disable_retries()
        self.test_get_keys_value_error()


class TestCreateKeyWithPoliciesOverrides:
    """
    Test Class for create_key_with_policies_overrides
    """

    @responses.activate
    def test_create_key_with_policies_overrides_all_params(self):
        """
        create_key_with_policies_overrides()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys_with_policy_overrides")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=201,
        )

        # Set up parameter values
        bluemix_instance = "testString"
        key_with_policy_overrides_create_body = io.BytesIO(b"This is a mock file.").getvalue()
        correlation_id = "testString"
        prefer = "return=representation"
        x_kms_key_ring = "default"

        # Invoke method
        response = _service.create_key_with_policies_overrides(
            bluemix_instance,
            key_with_policy_overrides_create_body,
            correlation_id=correlation_id,
            prefer=prefer,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        assert responses.calls[0].request.body == key_with_policy_overrides_create_body

    def test_create_key_with_policies_overrides_all_params_with_retries(self):
        # Enable retries and run test_create_key_with_policies_overrides_all_params.
        _service.enable_retries()
        self.test_create_key_with_policies_overrides_all_params()

        # Disable retries and run test_create_key_with_policies_overrides_all_params.
        _service.disable_retries()
        self.test_create_key_with_policies_overrides_all_params()

    @responses.activate
    def test_create_key_with_policies_overrides_required_params(self):
        """
        test_create_key_with_policies_overrides_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys_with_policy_overrides")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=201,
        )

        # Set up parameter values
        bluemix_instance = "testString"
        key_with_policy_overrides_create_body = io.BytesIO(b"This is a mock file.").getvalue()

        # Invoke method
        response = _service.create_key_with_policies_overrides(
            bluemix_instance,
            key_with_policy_overrides_create_body,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        assert responses.calls[0].request.body == key_with_policy_overrides_create_body

    def test_create_key_with_policies_overrides_required_params_with_retries(self):
        # Enable retries and run test_create_key_with_policies_overrides_required_params.
        _service.enable_retries()
        self.test_create_key_with_policies_overrides_required_params()

        # Disable retries and run test_create_key_with_policies_overrides_required_params.
        _service.disable_retries()
        self.test_create_key_with_policies_overrides_required_params()

    @responses.activate
    def test_create_key_with_policies_overrides_value_error(self):
        """
        test_create_key_with_policies_overrides_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys_with_policy_overrides")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=201,
        )

        # Set up parameter values
        bluemix_instance = "testString"
        key_with_policy_overrides_create_body = io.BytesIO(b"This is a mock file.").getvalue()

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bluemix_instance": bluemix_instance,
            "key_with_policy_overrides_create_body": key_with_policy_overrides_create_body,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_key_with_policies_overrides(**req_copy)

    def test_create_key_with_policies_overrides_value_error_with_retries(self):
        # Enable retries and run test_create_key_with_policies_overrides_value_error.
        _service.enable_retries()
        self.test_create_key_with_policies_overrides_value_error()

        # Disable retries and run test_create_key_with_policies_overrides_value_error.
        _service.disable_retries()
        self.test_create_key_with_policies_overrides_value_error()


class TestGetKey:
    """
    Test Class for get_key
    """

    @responses.activate
    def test_get_key_all_params(self):
        """
        get_key()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"

        # Invoke method
        response = _service.get_key(
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_key_all_params_with_retries(self):
        # Enable retries and run test_get_key_all_params.
        _service.enable_retries()
        self.test_get_key_all_params()

        # Disable retries and run test_get_key_all_params.
        _service.disable_retries()
        self.test_get_key_all_params()

    @responses.activate
    def test_get_key_required_params(self):
        """
        test_get_key_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_key(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_key_required_params_with_retries(self):
        # Enable retries and run test_get_key_required_params.
        _service.enable_retries()
        self.test_get_key_required_params()

        # Disable retries and run test_get_key_required_params.
        _service.disable_retries()
        self.test_get_key_required_params()

    @responses.activate
    def test_get_key_value_error(self):
        """
        test_get_key_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_key(**req_copy)

    def test_get_key_value_error_with_retries(self):
        # Enable retries and run test_get_key_value_error.
        _service.enable_retries()
        self.test_get_key_value_error()

        # Disable retries and run test_get_key_value_error.
        _service.disable_retries()
        self.test_get_key_value_error()


class TestActionOnKey:
    """
    Test Class for action_on_key
    """

    @responses.activate
    def test_action_on_key_all_params(self):
        """
        action_on_key()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString")
        mock_response = '{"plaintext": "plaintext", "ciphertext": "ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        action = "disable"
        key_action_body = io.BytesIO(b"This is a mock file.").getvalue()
        correlation_id = "testString"
        x_kms_key_ring = "testString"
        prefer = "return=representation"

        # Invoke method
        response = _service.action_on_key(
            id,
            bluemix_instance,
            action,
            key_action_body,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            prefer=prefer,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "action={}".format(action) in query_string
        # Validate body params
        assert responses.calls[0].request.body == key_action_body

    def test_action_on_key_all_params_with_retries(self):
        # Enable retries and run test_action_on_key_all_params.
        _service.enable_retries()
        self.test_action_on_key_all_params()

        # Disable retries and run test_action_on_key_all_params.
        _service.disable_retries()
        self.test_action_on_key_all_params()

    @responses.activate
    def test_action_on_key_required_params(self):
        """
        test_action_on_key_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString")
        mock_response = '{"plaintext": "plaintext", "ciphertext": "ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        action = "disable"
        key_action_body = io.BytesIO(b"This is a mock file.").getvalue()

        # Invoke method
        response = _service.action_on_key(
            id,
            bluemix_instance,
            action,
            key_action_body,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "action={}".format(action) in query_string
        # Validate body params
        assert responses.calls[0].request.body == key_action_body

    def test_action_on_key_required_params_with_retries(self):
        # Enable retries and run test_action_on_key_required_params.
        _service.enable_retries()
        self.test_action_on_key_required_params()

        # Disable retries and run test_action_on_key_required_params.
        _service.disable_retries()
        self.test_action_on_key_required_params()

    @responses.activate
    def test_action_on_key_value_error(self):
        """
        test_action_on_key_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString")
        mock_response = '{"plaintext": "plaintext", "ciphertext": "ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        action = "disable"
        key_action_body = io.BytesIO(b"This is a mock file.").getvalue()

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
            "action": action,
            "key_action_body": key_action_body,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.action_on_key(**req_copy)

    def test_action_on_key_value_error_with_retries(self):
        # Enable retries and run test_action_on_key_value_error.
        _service.enable_retries()
        self.test_action_on_key_value_error()

        # Disable retries and run test_action_on_key_value_error.
        _service.disable_retries()
        self.test_action_on_key_value_error()


class TestPatchKey:
    """
    Test Class for patch_key
    """

    @responses.activate
    def test_patch_key_all_params(self):
        """
        patch_key()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        key_patch_body = io.BytesIO(b"This is a mock file.").getvalue()
        correlation_id = "testString"
        x_kms_key_ring = "testString"

        # Invoke method
        response = _service.patch_key(
            id,
            bluemix_instance,
            key_patch_body=key_patch_body,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        assert responses.calls[0].request.body == key_patch_body

    def test_patch_key_all_params_with_retries(self):
        # Enable retries and run test_patch_key_all_params.
        _service.enable_retries()
        self.test_patch_key_all_params()

        # Disable retries and run test_patch_key_all_params.
        _service.disable_retries()
        self.test_patch_key_all_params()

    @responses.activate
    def test_patch_key_required_params(self):
        """
        test_patch_key_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.patch_key(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_patch_key_required_params_with_retries(self):
        # Enable retries and run test_patch_key_required_params.
        _service.enable_retries()
        self.test_patch_key_required_params()

        # Disable retries and run test_patch_key_required_params.
        _service.disable_retries()
        self.test_patch_key_required_params()

    @responses.activate
    def test_patch_key_value_error(self):
        """
        test_patch_key_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.patch_key(**req_copy)

    def test_patch_key_value_error_with_retries(self):
        # Enable retries and run test_patch_key_value_error.
        _service.enable_retries()
        self.test_patch_key_value_error()

        # Disable retries and run test_patch_key_value_error.
        _service.disable_retries()
        self.test_patch_key_value_error()


class TestDeleteKey:
    """
    Test Class for delete_key
    """

    @responses.activate
    def test_delete_key_all_params(self):
        """
        delete_key()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}'
        responses.add(
            responses.DELETE,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"
        prefer = "return=representation"
        force = False

        # Invoke method
        response = _service.delete_key(
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            prefer=prefer,
            force=force,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "force={}".format("true" if force else "false") in query_string

    def test_delete_key_all_params_with_retries(self):
        # Enable retries and run test_delete_key_all_params.
        _service.enable_retries()
        self.test_delete_key_all_params()

        # Disable retries and run test_delete_key_all_params.
        _service.disable_retries()
        self.test_delete_key_all_params()

    @responses.activate
    def test_delete_key_required_params(self):
        """
        test_delete_key_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}'
        responses.add(
            responses.DELETE,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.delete_key(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_delete_key_required_params_with_retries(self):
        # Enable retries and run test_delete_key_required_params.
        _service.enable_retries()
        self.test_delete_key_required_params()

        # Disable retries and run test_delete_key_required_params.
        _service.disable_retries()
        self.test_delete_key_required_params()

    @responses.activate
    def test_delete_key_value_error(self):
        """
        test_delete_key_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}'
        responses.add(
            responses.DELETE,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_key(**req_copy)

    def test_delete_key_value_error_with_retries(self):
        # Enable retries and run test_delete_key_value_error.
        _service.enable_retries()
        self.test_delete_key_value_error()

        # Disable retries and run test_delete_key_value_error.
        _service.disable_retries()
        self.test_delete_key_value_error()


class TestGetKeyMetadata:
    """
    Test Class for get_key_metadata
    """

    @responses.activate
    def test_get_key_metadata_all_params(self):
        """
        get_key_metadata()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/metadata")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"

        # Invoke method
        response = _service.get_key_metadata(
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_key_metadata_all_params_with_retries(self):
        # Enable retries and run test_get_key_metadata_all_params.
        _service.enable_retries()
        self.test_get_key_metadata_all_params()

        # Disable retries and run test_get_key_metadata_all_params.
        _service.disable_retries()
        self.test_get_key_metadata_all_params()

    @responses.activate
    def test_get_key_metadata_required_params(self):
        """
        test_get_key_metadata_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/metadata")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_key_metadata(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_key_metadata_required_params_with_retries(self):
        # Enable retries and run test_get_key_metadata_required_params.
        _service.enable_retries()
        self.test_get_key_metadata_required_params()

        # Disable retries and run test_get_key_metadata_required_params.
        _service.disable_retries()
        self.test_get_key_metadata_required_params()

    @responses.activate
    def test_get_key_metadata_value_error(self):
        """
        test_get_key_metadata_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/metadata")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_key_metadata(**req_copy)

    def test_get_key_metadata_value_error_with_retries(self):
        # Enable retries and run test_get_key_metadata_value_error.
        _service.enable_retries()
        self.test_get_key_metadata_value_error()

        # Disable retries and run test_get_key_metadata_value_error.
        _service.disable_retries()
        self.test_get_key_metadata_value_error()


class TestPurgeKey:
    """
    Test Class for purge_key
    """

    @responses.activate
    def test_purge_key_all_params(self):
        """
        purge_key()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/purge")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.DELETE,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"
        prefer = "return=representation"

        # Invoke method
        response = _service.purge_key(
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            prefer=prefer,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_purge_key_all_params_with_retries(self):
        # Enable retries and run test_purge_key_all_params.
        _service.enable_retries()
        self.test_purge_key_all_params()

        # Disable retries and run test_purge_key_all_params.
        _service.disable_retries()
        self.test_purge_key_all_params()

    @responses.activate
    def test_purge_key_required_params(self):
        """
        test_purge_key_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/purge")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.DELETE,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.purge_key(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_purge_key_required_params_with_retries(self):
        # Enable retries and run test_purge_key_required_params.
        _service.enable_retries()
        self.test_purge_key_required_params()

        # Disable retries and run test_purge_key_required_params.
        _service.disable_retries()
        self.test_purge_key_required_params()

    @responses.activate
    def test_purge_key_value_error(self):
        """
        test_purge_key_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/purge")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "id", "name": "name", "aliases": ["aliases"], "description": "description", "tags": ["tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "key_ring_id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 22, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "deleted_by", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": false, "purgeAllowed": false, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.DELETE,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.purge_key(**req_copy)

    def test_purge_key_value_error_with_retries(self):
        # Enable retries and run test_purge_key_value_error.
        _service.enable_retries()
        self.test_purge_key_value_error()

        # Disable retries and run test_purge_key_value_error.
        _service.disable_retries()
        self.test_purge_key_value_error()


class TestRestoreKey:
    """
    Test Class for restore_key
    """

    @responses.activate
    def test_restore_key_all_params(self):
        """
        restore_key()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/restore")
        mock_response = "This is a mock binary response."
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/vnd.ibm.kms.key+json",
            status=201,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"
        prefer = "return=representation"

        # Invoke method
        response = _service.restore_key(
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            prefer=prefer,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201

    def test_restore_key_all_params_with_retries(self):
        # Enable retries and run test_restore_key_all_params.
        _service.enable_retries()
        self.test_restore_key_all_params()

        # Disable retries and run test_restore_key_all_params.
        _service.disable_retries()
        self.test_restore_key_all_params()

    @responses.activate
    def test_restore_key_required_params(self):
        """
        test_restore_key_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/restore")
        mock_response = "This is a mock binary response."
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/vnd.ibm.kms.key+json",
            status=201,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.restore_key(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201

    def test_restore_key_required_params_with_retries(self):
        # Enable retries and run test_restore_key_required_params.
        _service.enable_retries()
        self.test_restore_key_required_params()

        # Disable retries and run test_restore_key_required_params.
        _service.disable_retries()
        self.test_restore_key_required_params()

    @responses.activate
    def test_restore_key_value_error(self):
        """
        test_restore_key_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/restore")
        mock_response = "This is a mock binary response."
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/vnd.ibm.kms.key+json",
            status=201,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.restore_key(**req_copy)

    def test_restore_key_value_error_with_retries(self):
        # Enable retries and run test_restore_key_value_error.
        _service.enable_retries()
        self.test_restore_key_value_error()

        # Disable retries and run test_restore_key_value_error.
        _service.disable_retries()
        self.test_restore_key_value_error()


class TestGetKeyVersions:
    """
    Test Class for get_key_versions
    """

    @responses.activate
    def test_get_key_versions_all_params(self):
        """
        get_key_versions()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/versions")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"
        limit = 200
        offset = 0
        total_count = True
        all_key_states = False

        # Invoke method
        response = _service.get_key_versions(
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            limit=limit,
            offset=offset,
            total_count=total_count,
            all_key_states=all_key_states,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "limit={}".format(limit) in query_string
        assert "offset={}".format(offset) in query_string
        assert "totalCount={}".format("true" if total_count else "false") in query_string
        assert "allKeyStates={}".format("true" if all_key_states else "false") in query_string

    def test_get_key_versions_all_params_with_retries(self):
        # Enable retries and run test_get_key_versions_all_params.
        _service.enable_retries()
        self.test_get_key_versions_all_params()

        # Disable retries and run test_get_key_versions_all_params.
        _service.disable_retries()
        self.test_get_key_versions_all_params()

    @responses.activate
    def test_get_key_versions_required_params(self):
        """
        test_get_key_versions_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/versions")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_key_versions(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_key_versions_required_params_with_retries(self):
        # Enable retries and run test_get_key_versions_required_params.
        _service.enable_retries()
        self.test_get_key_versions_required_params()

        # Disable retries and run test_get_key_versions_required_params.
        _service.disable_retries()
        self.test_get_key_versions_required_params()

    @responses.activate
    def test_get_key_versions_value_error(self):
        """
        test_get_key_versions_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/versions")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_key_versions(**req_copy)

    def test_get_key_versions_value_error_with_retries(self):
        # Enable retries and run test_get_key_versions_value_error.
        _service.enable_retries()
        self.test_get_key_versions_value_error()

        # Disable retries and run test_get_key_versions_value_error.
        _service.disable_retries()
        self.test_get_key_versions_value_error()


# endregion
##############################################################################
# End of Service: Keys
##############################################################################

##############################################################################
# Start of Service: KeyActions
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ["TEST_SERVICE_AUTH_TYPE"] = "noAuth"

        service = IbmKeyProtectApiV2.new_instance(
            service_name="TEST_SERVICE",
        )

        assert service is not None
        assert isinstance(service, IbmKeyProtectApiV2)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match="authenticator must be provided"):
            service = IbmKeyProtectApiV2.new_instance(
                service_name="TEST_SERVICE_NOT_FOUND",
            )


class TestWrapKey:
    """
    Test Class for wrap_key
    """

    @responses.activate
    def test_wrap_key_all_params(self):
        """
        wrap_key()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/wrap")
        mock_response = '{"plaintext": "plaintext", "ciphertext": "ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        key_action_wrap_body = io.BytesIO(b"This is a mock file.").getvalue()
        correlation_id = "testString"
        x_kms_key_ring = "testString"

        # Invoke method
        response = _service.wrap_key(
            id,
            bluemix_instance,
            key_action_wrap_body=key_action_wrap_body,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        assert responses.calls[0].request.body == key_action_wrap_body

    def test_wrap_key_all_params_with_retries(self):
        # Enable retries and run test_wrap_key_all_params.
        _service.enable_retries()
        self.test_wrap_key_all_params()

        # Disable retries and run test_wrap_key_all_params.
        _service.disable_retries()
        self.test_wrap_key_all_params()

    @responses.activate
    def test_wrap_key_required_params(self):
        """
        test_wrap_key_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/wrap")
        mock_response = '{"plaintext": "plaintext", "ciphertext": "ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.wrap_key(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_wrap_key_required_params_with_retries(self):
        # Enable retries and run test_wrap_key_required_params.
        _service.enable_retries()
        self.test_wrap_key_required_params()

        # Disable retries and run test_wrap_key_required_params.
        _service.disable_retries()
        self.test_wrap_key_required_params()

    @responses.activate
    def test_wrap_key_value_error(self):
        """
        test_wrap_key_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/wrap")
        mock_response = '{"plaintext": "plaintext", "ciphertext": "ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.wrap_key(**req_copy)

    def test_wrap_key_value_error_with_retries(self):
        # Enable retries and run test_wrap_key_value_error.
        _service.enable_retries()
        self.test_wrap_key_value_error()

        # Disable retries and run test_wrap_key_value_error.
        _service.disable_retries()
        self.test_wrap_key_value_error()


class TestUnwrapKey:
    """
    Test Class for unwrap_key
    """

    @responses.activate
    def test_unwrap_key_all_params(self):
        """
        unwrap_key()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/unwrap")
        mock_response = '{"plaintext": "plaintext", "ciphertext": "ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}, "rewrappedKeyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        key_action_unwrap_body = io.BytesIO(b"This is a mock file.").getvalue()
        correlation_id = "testString"
        x_kms_key_ring = "testString"

        # Invoke method
        response = _service.unwrap_key(
            id,
            bluemix_instance,
            key_action_unwrap_body,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        assert responses.calls[0].request.body == key_action_unwrap_body

    def test_unwrap_key_all_params_with_retries(self):
        # Enable retries and run test_unwrap_key_all_params.
        _service.enable_retries()
        self.test_unwrap_key_all_params()

        # Disable retries and run test_unwrap_key_all_params.
        _service.disable_retries()
        self.test_unwrap_key_all_params()

    @responses.activate
    def test_unwrap_key_required_params(self):
        """
        test_unwrap_key_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/unwrap")
        mock_response = '{"plaintext": "plaintext", "ciphertext": "ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}, "rewrappedKeyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        key_action_unwrap_body = io.BytesIO(b"This is a mock file.").getvalue()

        # Invoke method
        response = _service.unwrap_key(
            id,
            bluemix_instance,
            key_action_unwrap_body,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        assert responses.calls[0].request.body == key_action_unwrap_body

    def test_unwrap_key_required_params_with_retries(self):
        # Enable retries and run test_unwrap_key_required_params.
        _service.enable_retries()
        self.test_unwrap_key_required_params()

        # Disable retries and run test_unwrap_key_required_params.
        _service.disable_retries()
        self.test_unwrap_key_required_params()

    @responses.activate
    def test_unwrap_key_value_error(self):
        """
        test_unwrap_key_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/unwrap")
        mock_response = '{"plaintext": "plaintext", "ciphertext": "ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}, "rewrappedKeyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        key_action_unwrap_body = io.BytesIO(b"This is a mock file.").getvalue()

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
            "key_action_unwrap_body": key_action_unwrap_body,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.unwrap_key(**req_copy)

    def test_unwrap_key_value_error_with_retries(self):
        # Enable retries and run test_unwrap_key_value_error.
        _service.enable_retries()
        self.test_unwrap_key_value_error()

        # Disable retries and run test_unwrap_key_value_error.
        _service.disable_retries()
        self.test_unwrap_key_value_error()


class TestRewrapKey:
    """
    Test Class for rewrap_key
    """

    @responses.activate
    def test_rewrap_key_all_params(self):
        """
        rewrap_key()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/rewrap")
        mock_response = '{"ciphertext": "ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}, "rewrappedKeyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        key_action_rewrap_body = io.BytesIO(b"This is a mock file.").getvalue()
        correlation_id = "testString"
        x_kms_key_ring = "testString"

        # Invoke method
        response = _service.rewrap_key(
            id,
            bluemix_instance,
            key_action_rewrap_body,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        assert responses.calls[0].request.body == key_action_rewrap_body

    def test_rewrap_key_all_params_with_retries(self):
        # Enable retries and run test_rewrap_key_all_params.
        _service.enable_retries()
        self.test_rewrap_key_all_params()

        # Disable retries and run test_rewrap_key_all_params.
        _service.disable_retries()
        self.test_rewrap_key_all_params()

    @responses.activate
    def test_rewrap_key_required_params(self):
        """
        test_rewrap_key_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/rewrap")
        mock_response = '{"ciphertext": "ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}, "rewrappedKeyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        key_action_rewrap_body = io.BytesIO(b"This is a mock file.").getvalue()

        # Invoke method
        response = _service.rewrap_key(
            id,
            bluemix_instance,
            key_action_rewrap_body,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        assert responses.calls[0].request.body == key_action_rewrap_body

    def test_rewrap_key_required_params_with_retries(self):
        # Enable retries and run test_rewrap_key_required_params.
        _service.enable_retries()
        self.test_rewrap_key_required_params()

        # Disable retries and run test_rewrap_key_required_params.
        _service.disable_retries()
        self.test_rewrap_key_required_params()

    @responses.activate
    def test_rewrap_key_value_error(self):
        """
        test_rewrap_key_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/rewrap")
        mock_response = '{"ciphertext": "ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}, "rewrappedKeyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        key_action_rewrap_body = io.BytesIO(b"This is a mock file.").getvalue()

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
            "key_action_rewrap_body": key_action_rewrap_body,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.rewrap_key(**req_copy)

    def test_rewrap_key_value_error_with_retries(self):
        # Enable retries and run test_rewrap_key_value_error.
        _service.enable_retries()
        self.test_rewrap_key_value_error()

        # Disable retries and run test_rewrap_key_value_error.
        _service.disable_retries()
        self.test_rewrap_key_value_error()


class TestRotateKey:
    """
    Test Class for rotate_key
    """

    @responses.activate
    def test_rotate_key_all_params(self):
        """
        rotate_key()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/rotate")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        key_action_rotate_body = io.BytesIO(b"This is a mock file.").getvalue()
        correlation_id = "testString"
        x_kms_key_ring = "testString"
        prefer = "return=representation"

        # Invoke method
        response = _service.rotate_key(
            id,
            bluemix_instance,
            key_action_rotate_body=key_action_rotate_body,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            prefer=prefer,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        assert responses.calls[0].request.body == key_action_rotate_body

    def test_rotate_key_all_params_with_retries(self):
        # Enable retries and run test_rotate_key_all_params.
        _service.enable_retries()
        self.test_rotate_key_all_params()

        # Disable retries and run test_rotate_key_all_params.
        _service.disable_retries()
        self.test_rotate_key_all_params()

    @responses.activate
    def test_rotate_key_required_params(self):
        """
        test_rotate_key_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/rotate")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.rotate_key(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_rotate_key_required_params_with_retries(self):
        # Enable retries and run test_rotate_key_required_params.
        _service.enable_retries()
        self.test_rotate_key_required_params()

        # Disable retries and run test_rotate_key_required_params.
        _service.disable_retries()
        self.test_rotate_key_required_params()

    @responses.activate
    def test_rotate_key_value_error(self):
        """
        test_rotate_key_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/rotate")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.rotate_key(**req_copy)

    def test_rotate_key_value_error_with_retries(self):
        # Enable retries and run test_rotate_key_value_error.
        _service.enable_retries()
        self.test_rotate_key_value_error()

        # Disable retries and run test_rotate_key_value_error.
        _service.disable_retries()
        self.test_rotate_key_value_error()


class TestSetKeyForDeletion:
    """
    Test Class for set_key_for_deletion
    """

    @responses.activate
    def test_set_key_for_deletion_all_params(self):
        """
        set_key_for_deletion()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/setKeyForDeletion")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"

        # Invoke method
        response = _service.set_key_for_deletion(
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_set_key_for_deletion_all_params_with_retries(self):
        # Enable retries and run test_set_key_for_deletion_all_params.
        _service.enable_retries()
        self.test_set_key_for_deletion_all_params()

        # Disable retries and run test_set_key_for_deletion_all_params.
        _service.disable_retries()
        self.test_set_key_for_deletion_all_params()

    @responses.activate
    def test_set_key_for_deletion_required_params(self):
        """
        test_set_key_for_deletion_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/setKeyForDeletion")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.set_key_for_deletion(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_set_key_for_deletion_required_params_with_retries(self):
        # Enable retries and run test_set_key_for_deletion_required_params.
        _service.enable_retries()
        self.test_set_key_for_deletion_required_params()

        # Disable retries and run test_set_key_for_deletion_required_params.
        _service.disable_retries()
        self.test_set_key_for_deletion_required_params()

    @responses.activate
    def test_set_key_for_deletion_value_error(self):
        """
        test_set_key_for_deletion_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/setKeyForDeletion")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.set_key_for_deletion(**req_copy)

    def test_set_key_for_deletion_value_error_with_retries(self):
        # Enable retries and run test_set_key_for_deletion_value_error.
        _service.enable_retries()
        self.test_set_key_for_deletion_value_error()

        # Disable retries and run test_set_key_for_deletion_value_error.
        _service.disable_retries()
        self.test_set_key_for_deletion_value_error()


class TestUnsetKeyForDeletion:
    """
    Test Class for unset_key_for_deletion
    """

    @responses.activate
    def test_unset_key_for_deletion_all_params(self):
        """
        unset_key_for_deletion()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/unsetKeyForDeletion")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"

        # Invoke method
        response = _service.unset_key_for_deletion(
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_unset_key_for_deletion_all_params_with_retries(self):
        # Enable retries and run test_unset_key_for_deletion_all_params.
        _service.enable_retries()
        self.test_unset_key_for_deletion_all_params()

        # Disable retries and run test_unset_key_for_deletion_all_params.
        _service.disable_retries()
        self.test_unset_key_for_deletion_all_params()

    @responses.activate
    def test_unset_key_for_deletion_required_params(self):
        """
        test_unset_key_for_deletion_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/unsetKeyForDeletion")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.unset_key_for_deletion(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_unset_key_for_deletion_required_params_with_retries(self):
        # Enable retries and run test_unset_key_for_deletion_required_params.
        _service.enable_retries()
        self.test_unset_key_for_deletion_required_params()

        # Disable retries and run test_unset_key_for_deletion_required_params.
        _service.disable_retries()
        self.test_unset_key_for_deletion_required_params()

    @responses.activate
    def test_unset_key_for_deletion_value_error(self):
        """
        test_unset_key_for_deletion_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/unsetKeyForDeletion")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.unset_key_for_deletion(**req_copy)

    def test_unset_key_for_deletion_value_error_with_retries(self):
        # Enable retries and run test_unset_key_for_deletion_value_error.
        _service.enable_retries()
        self.test_unset_key_for_deletion_value_error()

        # Disable retries and run test_unset_key_for_deletion_value_error.
        _service.disable_retries()
        self.test_unset_key_for_deletion_value_error()


class TestEnableKey:
    """
    Test Class for enable_key
    """

    @responses.activate
    def test_enable_key_all_params(self):
        """
        enable_key()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/enable")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"

        # Invoke method
        response = _service.enable_key(
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_enable_key_all_params_with_retries(self):
        # Enable retries and run test_enable_key_all_params.
        _service.enable_retries()
        self.test_enable_key_all_params()

        # Disable retries and run test_enable_key_all_params.
        _service.disable_retries()
        self.test_enable_key_all_params()

    @responses.activate
    def test_enable_key_required_params(self):
        """
        test_enable_key_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/enable")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.enable_key(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_enable_key_required_params_with_retries(self):
        # Enable retries and run test_enable_key_required_params.
        _service.enable_retries()
        self.test_enable_key_required_params()

        # Disable retries and run test_enable_key_required_params.
        _service.disable_retries()
        self.test_enable_key_required_params()

    @responses.activate
    def test_enable_key_value_error(self):
        """
        test_enable_key_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/enable")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.enable_key(**req_copy)

    def test_enable_key_value_error_with_retries(self):
        # Enable retries and run test_enable_key_value_error.
        _service.enable_retries()
        self.test_enable_key_value_error()

        # Disable retries and run test_enable_key_value_error.
        _service.disable_retries()
        self.test_enable_key_value_error()


class TestDisableKey:
    """
    Test Class for disable_key
    """

    @responses.activate
    def test_disable_key_all_params(self):
        """
        disable_key()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/disable")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"

        # Invoke method
        response = _service.disable_key(
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_disable_key_all_params_with_retries(self):
        # Enable retries and run test_disable_key_all_params.
        _service.enable_retries()
        self.test_disable_key_all_params()

        # Disable retries and run test_disable_key_all_params.
        _service.disable_retries()
        self.test_disable_key_all_params()

    @responses.activate
    def test_disable_key_required_params(self):
        """
        test_disable_key_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/disable")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.disable_key(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_disable_key_required_params_with_retries(self):
        # Enable retries and run test_disable_key_required_params.
        _service.enable_retries()
        self.test_disable_key_required_params()

        # Disable retries and run test_disable_key_required_params.
        _service.disable_retries()
        self.test_disable_key_required_params()

    @responses.activate
    def test_disable_key_value_error(self):
        """
        test_disable_key_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/disable")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.disable_key(**req_copy)

    def test_disable_key_value_error_with_retries(self):
        # Enable retries and run test_disable_key_value_error.
        _service.enable_retries()
        self.test_disable_key_value_error()

        # Disable retries and run test_disable_key_value_error.
        _service.disable_retries()
        self.test_disable_key_value_error()


class TestSyncAssociatedResources:
    """
    Test Class for sync_associated_resources
    """

    @responses.activate
    def test_sync_associated_resources_all_params(self):
        """
        sync_associated_resources()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/sync")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"

        # Invoke method
        response = _service.sync_associated_resources(
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_sync_associated_resources_all_params_with_retries(self):
        # Enable retries and run test_sync_associated_resources_all_params.
        _service.enable_retries()
        self.test_sync_associated_resources_all_params()

        # Disable retries and run test_sync_associated_resources_all_params.
        _service.disable_retries()
        self.test_sync_associated_resources_all_params()

    @responses.activate
    def test_sync_associated_resources_required_params(self):
        """
        test_sync_associated_resources_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/sync")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.sync_associated_resources(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_sync_associated_resources_required_params_with_retries(self):
        # Enable retries and run test_sync_associated_resources_required_params.
        _service.enable_retries()
        self.test_sync_associated_resources_required_params()

        # Disable retries and run test_sync_associated_resources_required_params.
        _service.disable_retries()
        self.test_sync_associated_resources_required_params()

    @responses.activate
    def test_sync_associated_resources_value_error(self):
        """
        test_sync_associated_resources_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/actions/sync")
        responses.add(
            responses.POST,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.sync_associated_resources(**req_copy)

    def test_sync_associated_resources_value_error_with_retries(self):
        # Enable retries and run test_sync_associated_resources_value_error.
        _service.enable_retries()
        self.test_sync_associated_resources_value_error()

        # Disable retries and run test_sync_associated_resources_value_error.
        _service.disable_retries()
        self.test_sync_associated_resources_value_error()


# endregion
##############################################################################
# End of Service: KeyActions
##############################################################################

##############################################################################
# Start of Service: Policies
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ["TEST_SERVICE_AUTH_TYPE"] = "noAuth"

        service = IbmKeyProtectApiV2.new_instance(
            service_name="TEST_SERVICE",
        )

        assert service is not None
        assert isinstance(service, IbmKeyProtectApiV2)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match="authenticator must be provided"):
            service = IbmKeyProtectApiV2.new_instance(
                service_name="TEST_SERVICE_NOT_FOUND",
            )


class TestPutPolicy:
    """
    Test Class for put_policy
    """

    @responses.activate
    def test_put_policy_all_params(self):
        """
        put_policy()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/policies")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:policy:<policy-id>", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "lastUpdateDate": "2000-03-21T00:00:00.000Z", "updatedBy": "updated_by", "type": "application/vnd.ibm.kms.policy+json", "dualAuthDelete": {"enabled": true}}]}'
        responses.add(
            responses.PUT,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.policy+json"
        collection_metadata_model["collectionTotal"] = 1

        # Construct a dict representation of a KeyPolicyDualAuthDeleteDualAuthDelete model
        key_policy_dual_auth_delete_dual_auth_delete_model = {}
        key_policy_dual_auth_delete_dual_auth_delete_model["enabled"] = True

        # Construct a dict representation of a KeyPolicyDualAuthDelete model
        key_policy_dual_auth_delete_model = {}
        key_policy_dual_auth_delete_model["type"] = "application/vnd.ibm.kms.policy+json"
        key_policy_dual_auth_delete_model["dualAuthDelete"] = key_policy_dual_auth_delete_dual_auth_delete_model

        # Construct a dict representation of a SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete model
        set_key_policies_one_of_model = {}
        set_key_policies_one_of_model["metadata"] = collection_metadata_model
        set_key_policies_one_of_model["resources"] = [key_policy_dual_auth_delete_model]

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        key_policy_put_body = set_key_policies_one_of_model
        correlation_id = "testString"
        x_kms_key_ring = "testString"
        policy = "dualAuthDelete"

        # Invoke method
        response = _service.put_policy(
            id,
            bluemix_instance,
            key_policy_put_body,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            policy=policy,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "policy={}".format(policy) in query_string
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, "utf-8"))
        assert req_body == key_policy_put_body

    def test_put_policy_all_params_with_retries(self):
        # Enable retries and run test_put_policy_all_params.
        _service.enable_retries()
        self.test_put_policy_all_params()

        # Disable retries and run test_put_policy_all_params.
        _service.disable_retries()
        self.test_put_policy_all_params()

    @responses.activate
    def test_put_policy_required_params(self):
        """
        test_put_policy_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/policies")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:policy:<policy-id>", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "lastUpdateDate": "2000-03-21T00:00:00.000Z", "updatedBy": "updated_by", "type": "application/vnd.ibm.kms.policy+json", "dualAuthDelete": {"enabled": true}}]}'
        responses.add(
            responses.PUT,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.policy+json"
        collection_metadata_model["collectionTotal"] = 1

        # Construct a dict representation of a KeyPolicyDualAuthDeleteDualAuthDelete model
        key_policy_dual_auth_delete_dual_auth_delete_model = {}
        key_policy_dual_auth_delete_dual_auth_delete_model["enabled"] = True

        # Construct a dict representation of a KeyPolicyDualAuthDelete model
        key_policy_dual_auth_delete_model = {}
        key_policy_dual_auth_delete_model["type"] = "application/vnd.ibm.kms.policy+json"
        key_policy_dual_auth_delete_model["dualAuthDelete"] = key_policy_dual_auth_delete_dual_auth_delete_model

        # Construct a dict representation of a SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete model
        set_key_policies_one_of_model = {}
        set_key_policies_one_of_model["metadata"] = collection_metadata_model
        set_key_policies_one_of_model["resources"] = [key_policy_dual_auth_delete_model]

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        key_policy_put_body = set_key_policies_one_of_model

        # Invoke method
        response = _service.put_policy(
            id,
            bluemix_instance,
            key_policy_put_body,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, "utf-8"))
        assert req_body == key_policy_put_body

    def test_put_policy_required_params_with_retries(self):
        # Enable retries and run test_put_policy_required_params.
        _service.enable_retries()
        self.test_put_policy_required_params()

        # Disable retries and run test_put_policy_required_params.
        _service.disable_retries()
        self.test_put_policy_required_params()

    @responses.activate
    def test_put_policy_value_error(self):
        """
        test_put_policy_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/policies")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:policy:<policy-id>", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "lastUpdateDate": "2000-03-21T00:00:00.000Z", "updatedBy": "updated_by", "type": "application/vnd.ibm.kms.policy+json", "dualAuthDelete": {"enabled": true}}]}'
        responses.add(
            responses.PUT,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.policy+json"
        collection_metadata_model["collectionTotal"] = 1

        # Construct a dict representation of a KeyPolicyDualAuthDeleteDualAuthDelete model
        key_policy_dual_auth_delete_dual_auth_delete_model = {}
        key_policy_dual_auth_delete_dual_auth_delete_model["enabled"] = True

        # Construct a dict representation of a KeyPolicyDualAuthDelete model
        key_policy_dual_auth_delete_model = {}
        key_policy_dual_auth_delete_model["type"] = "application/vnd.ibm.kms.policy+json"
        key_policy_dual_auth_delete_model["dualAuthDelete"] = key_policy_dual_auth_delete_dual_auth_delete_model

        # Construct a dict representation of a SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete model
        set_key_policies_one_of_model = {}
        set_key_policies_one_of_model["metadata"] = collection_metadata_model
        set_key_policies_one_of_model["resources"] = [key_policy_dual_auth_delete_model]

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        key_policy_put_body = set_key_policies_one_of_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
            "key_policy_put_body": key_policy_put_body,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.put_policy(**req_copy)

    def test_put_policy_value_error_with_retries(self):
        # Enable retries and run test_put_policy_value_error.
        _service.enable_retries()
        self.test_put_policy_value_error()

        # Disable retries and run test_put_policy_value_error.
        _service.disable_retries()
        self.test_put_policy_value_error()


class TestGetPolicy:
    """
    Test Class for get_policy
    """

    @responses.activate
    def test_get_policy_all_params(self):
        """
        get_policy()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/policies")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:policy:<policy-id>", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "lastUpdateDate": "2000-03-21T00:00:00.000Z", "updatedBy": "updated_by", "type": "application/vnd.ibm.kms.policy+json", "dualAuthDelete": {"enabled": true}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"
        policy = "dualAuthDelete"

        # Invoke method
        response = _service.get_policy(
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            policy=policy,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "policy={}".format(policy) in query_string

    def test_get_policy_all_params_with_retries(self):
        # Enable retries and run test_get_policy_all_params.
        _service.enable_retries()
        self.test_get_policy_all_params()

        # Disable retries and run test_get_policy_all_params.
        _service.disable_retries()
        self.test_get_policy_all_params()

    @responses.activate
    def test_get_policy_required_params(self):
        """
        test_get_policy_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/policies")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:policy:<policy-id>", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "lastUpdateDate": "2000-03-21T00:00:00.000Z", "updatedBy": "updated_by", "type": "application/vnd.ibm.kms.policy+json", "dualAuthDelete": {"enabled": true}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_policy(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_policy_required_params_with_retries(self):
        # Enable retries and run test_get_policy_required_params.
        _service.enable_retries()
        self.test_get_policy_required_params()

        # Disable retries and run test_get_policy_required_params.
        _service.disable_retries()
        self.test_get_policy_required_params()

    @responses.activate
    def test_get_policy_value_error(self):
        """
        test_get_policy_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/policies")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:policy:<policy-id>", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "lastUpdateDate": "2000-03-21T00:00:00.000Z", "updatedBy": "updated_by", "type": "application/vnd.ibm.kms.policy+json", "dualAuthDelete": {"enabled": true}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_policy(**req_copy)

    def test_get_policy_value_error_with_retries(self):
        # Enable retries and run test_get_policy_value_error.
        _service.enable_retries()
        self.test_get_policy_value_error()

        # Disable retries and run test_get_policy_value_error.
        _service.disable_retries()
        self.test_get_policy_value_error()


class TestPutInstancePolicy:
    """
    Test Class for put_instance_policy
    """

    @responses.activate
    def test_put_instance_policy_all_params(self):
        """
        put_instance_policy()
        """
        # Set up mock
        url = preprocess_url("/api/v2/instance/policies")
        responses.add(
            responses.PUT,
            url,
            status=204,
        )

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.policy+json"
        collection_metadata_model["collectionTotal"] = 1

        # Construct a dict representation of a InstancePolicyAllowedNetworkPolicyDataAttributes model
        instance_policy_allowed_network_policy_data_attributes_model = {}
        instance_policy_allowed_network_policy_data_attributes_model["allowed_network"] = "private-only"

        # Construct a dict representation of a InstancePolicyAllowedNetworkPolicyData model
        instance_policy_allowed_network_policy_data_model = {}
        instance_policy_allowed_network_policy_data_model["enabled"] = True
        instance_policy_allowed_network_policy_data_model[
            "attributes"
        ] = instance_policy_allowed_network_policy_data_attributes_model

        # Construct a dict representation of a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem model
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model = {}
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model[
            "policy_type"
        ] = "allowedNetwork"
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model[
            "policy_data"
        ] = instance_policy_allowed_network_policy_data_model

        # Construct a dict representation of a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork model
        set_instance_policies_one_of_model = {}
        set_instance_policies_one_of_model["metadata"] = collection_metadata_model
        set_instance_policies_one_of_model["resources"] = [
            set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model
        ]

        # Set up parameter values
        bluemix_instance = "testString"
        instance_policy_put_body = set_instance_policies_one_of_model
        correlation_id = "testString"
        policy = "allowedNetwork"

        # Invoke method
        response = _service.put_instance_policy(
            bluemix_instance,
            instance_policy_put_body,
            correlation_id=correlation_id,
            policy=policy,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "policy={}".format(policy) in query_string
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, "utf-8"))
        assert req_body == instance_policy_put_body

    def test_put_instance_policy_all_params_with_retries(self):
        # Enable retries and run test_put_instance_policy_all_params.
        _service.enable_retries()
        self.test_put_instance_policy_all_params()

        # Disable retries and run test_put_instance_policy_all_params.
        _service.disable_retries()
        self.test_put_instance_policy_all_params()

    @responses.activate
    def test_put_instance_policy_required_params(self):
        """
        test_put_instance_policy_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/instance/policies")
        responses.add(
            responses.PUT,
            url,
            status=204,
        )

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.policy+json"
        collection_metadata_model["collectionTotal"] = 1

        # Construct a dict representation of a InstancePolicyAllowedNetworkPolicyDataAttributes model
        instance_policy_allowed_network_policy_data_attributes_model = {}
        instance_policy_allowed_network_policy_data_attributes_model["allowed_network"] = "private-only"

        # Construct a dict representation of a InstancePolicyAllowedNetworkPolicyData model
        instance_policy_allowed_network_policy_data_model = {}
        instance_policy_allowed_network_policy_data_model["enabled"] = True
        instance_policy_allowed_network_policy_data_model[
            "attributes"
        ] = instance_policy_allowed_network_policy_data_attributes_model

        # Construct a dict representation of a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem model
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model = {}
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model[
            "policy_type"
        ] = "allowedNetwork"
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model[
            "policy_data"
        ] = instance_policy_allowed_network_policy_data_model

        # Construct a dict representation of a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork model
        set_instance_policies_one_of_model = {}
        set_instance_policies_one_of_model["metadata"] = collection_metadata_model
        set_instance_policies_one_of_model["resources"] = [
            set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model
        ]

        # Set up parameter values
        bluemix_instance = "testString"
        instance_policy_put_body = set_instance_policies_one_of_model

        # Invoke method
        response = _service.put_instance_policy(
            bluemix_instance,
            instance_policy_put_body,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, "utf-8"))
        assert req_body == instance_policy_put_body

    def test_put_instance_policy_required_params_with_retries(self):
        # Enable retries and run test_put_instance_policy_required_params.
        _service.enable_retries()
        self.test_put_instance_policy_required_params()

        # Disable retries and run test_put_instance_policy_required_params.
        _service.disable_retries()
        self.test_put_instance_policy_required_params()

    @responses.activate
    def test_put_instance_policy_value_error(self):
        """
        test_put_instance_policy_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/instance/policies")
        responses.add(
            responses.PUT,
            url,
            status=204,
        )

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.policy+json"
        collection_metadata_model["collectionTotal"] = 1

        # Construct a dict representation of a InstancePolicyAllowedNetworkPolicyDataAttributes model
        instance_policy_allowed_network_policy_data_attributes_model = {}
        instance_policy_allowed_network_policy_data_attributes_model["allowed_network"] = "private-only"

        # Construct a dict representation of a InstancePolicyAllowedNetworkPolicyData model
        instance_policy_allowed_network_policy_data_model = {}
        instance_policy_allowed_network_policy_data_model["enabled"] = True
        instance_policy_allowed_network_policy_data_model[
            "attributes"
        ] = instance_policy_allowed_network_policy_data_attributes_model

        # Construct a dict representation of a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem model
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model = {}
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model[
            "policy_type"
        ] = "allowedNetwork"
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model[
            "policy_data"
        ] = instance_policy_allowed_network_policy_data_model

        # Construct a dict representation of a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork model
        set_instance_policies_one_of_model = {}
        set_instance_policies_one_of_model["metadata"] = collection_metadata_model
        set_instance_policies_one_of_model["resources"] = [
            set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model
        ]

        # Set up parameter values
        bluemix_instance = "testString"
        instance_policy_put_body = set_instance_policies_one_of_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bluemix_instance": bluemix_instance,
            "instance_policy_put_body": instance_policy_put_body,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.put_instance_policy(**req_copy)

    def test_put_instance_policy_value_error_with_retries(self):
        # Enable retries and run test_put_instance_policy_value_error.
        _service.enable_retries()
        self.test_put_instance_policy_value_error()

        # Disable retries and run test_put_instance_policy_value_error.
        _service.disable_retries()
        self.test_put_instance_policy_value_error()


class TestGetInstancePolicy:
    """
    Test Class for get_instance_policy
    """

    @responses.activate
    def test_get_instance_policy_all_params(self):
        """
        get_instance_policy()
        """
        # Set up mock
        url = preprocess_url("/api/v2/instance/policies")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "updatedBy": "updated_by", "lastUpdated": "2000-03-21T00:00:00.000Z", "policy_type": "policy_type", "policy_data": {"enabled": true, "attributes": {"allowed_network": "public-and-private"}}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"
        correlation_id = "testString"
        policy = "allowedNetwork"

        # Invoke method
        response = _service.get_instance_policy(
            bluemix_instance,
            correlation_id=correlation_id,
            policy=policy,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "policy={}".format(policy) in query_string

    def test_get_instance_policy_all_params_with_retries(self):
        # Enable retries and run test_get_instance_policy_all_params.
        _service.enable_retries()
        self.test_get_instance_policy_all_params()

        # Disable retries and run test_get_instance_policy_all_params.
        _service.disable_retries()
        self.test_get_instance_policy_all_params()

    @responses.activate
    def test_get_instance_policy_required_params(self):
        """
        test_get_instance_policy_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/instance/policies")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "updatedBy": "updated_by", "lastUpdated": "2000-03-21T00:00:00.000Z", "policy_type": "policy_type", "policy_data": {"enabled": true, "attributes": {"allowed_network": "public-and-private"}}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_instance_policy(
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_instance_policy_required_params_with_retries(self):
        # Enable retries and run test_get_instance_policy_required_params.
        _service.enable_retries()
        self.test_get_instance_policy_required_params()

        # Disable retries and run test_get_instance_policy_required_params.
        _service.disable_retries()
        self.test_get_instance_policy_required_params()

    @responses.activate
    def test_get_instance_policy_value_error(self):
        """
        test_get_instance_policy_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/instance/policies")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by", "updatedBy": "updated_by", "lastUpdated": "2000-03-21T00:00:00.000Z", "policy_type": "policy_type", "policy_data": {"enabled": true, "attributes": {"allowed_network": "public-and-private"}}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_instance_policy(**req_copy)

    def test_get_instance_policy_value_error_with_retries(self):
        # Enable retries and run test_get_instance_policy_value_error.
        _service.enable_retries()
        self.test_get_instance_policy_value_error()

        # Disable retries and run test_get_instance_policy_value_error.
        _service.disable_retries()
        self.test_get_instance_policy_value_error()


class TestGetAllowedIpPort:
    """
    Test Class for get_allowed_ip_port
    """

    @responses.activate
    def test_get_allowed_ip_port_all_params(self):
        """
        get_allowed_ip_port()
        """
        # Set up mock
        url = preprocess_url("/api/v2/instance/allowed_ip_port")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"private_endpoint_port": 8888}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"
        correlation_id = "testString"

        # Invoke method
        response = _service.get_allowed_ip_port(
            bluemix_instance,
            correlation_id=correlation_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_allowed_ip_port_all_params_with_retries(self):
        # Enable retries and run test_get_allowed_ip_port_all_params.
        _service.enable_retries()
        self.test_get_allowed_ip_port_all_params()

        # Disable retries and run test_get_allowed_ip_port_all_params.
        _service.disable_retries()
        self.test_get_allowed_ip_port_all_params()

    @responses.activate
    def test_get_allowed_ip_port_required_params(self):
        """
        test_get_allowed_ip_port_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/instance/allowed_ip_port")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"private_endpoint_port": 8888}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_allowed_ip_port(
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_allowed_ip_port_required_params_with_retries(self):
        # Enable retries and run test_get_allowed_ip_port_required_params.
        _service.enable_retries()
        self.test_get_allowed_ip_port_required_params()

        # Disable retries and run test_get_allowed_ip_port_required_params.
        _service.disable_retries()
        self.test_get_allowed_ip_port_required_params()

    @responses.activate
    def test_get_allowed_ip_port_value_error(self):
        """
        test_get_allowed_ip_port_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/instance/allowed_ip_port")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"private_endpoint_port": 8888}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_allowed_ip_port(**req_copy)

    def test_get_allowed_ip_port_value_error_with_retries(self):
        # Enable retries and run test_get_allowed_ip_port_value_error.
        _service.enable_retries()
        self.test_get_allowed_ip_port_value_error()

        # Disable retries and run test_get_allowed_ip_port_value_error.
        _service.disable_retries()
        self.test_get_allowed_ip_port_value_error()


# endregion
##############################################################################
# End of Service: Policies
##############################################################################

##############################################################################
# Start of Service: ImportTokens
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ["TEST_SERVICE_AUTH_TYPE"] = "noAuth"

        service = IbmKeyProtectApiV2.new_instance(
            service_name="TEST_SERVICE",
        )

        assert service is not None
        assert isinstance(service, IbmKeyProtectApiV2)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match="authenticator must be provided"):
            service = IbmKeyProtectApiV2.new_instance(
                service_name="TEST_SERVICE_NOT_FOUND",
            )


class TestPostImportToken:
    """
    Test Class for post_import_token
    """

    @responses.activate
    def test_post_import_token_all_params(self):
        """
        post_import_token()
        """
        # Set up mock
        url = preprocess_url("/api/v2/import_token")
        mock_response = '{"expiration": 600, "maxAllowedRetrievals": 1, "creationDate": "2000-03-21T00:00:00.000Z", "expirationDate": "2000-03-21T00:00:00.000Z", "remainingRetrievals": 1}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"
        expiration = 600
        max_allowed_retrievals = 1
        correlation_id = "testString"
        x_kms_key_ring = "default"

        # Invoke method
        response = _service.post_import_token(
            bluemix_instance,
            expiration=expiration,
            max_allowed_retrievals=max_allowed_retrievals,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, "utf-8"))
        assert req_body["expiration"] == 600
        assert req_body["maxAllowedRetrievals"] == 1

    def test_post_import_token_all_params_with_retries(self):
        # Enable retries and run test_post_import_token_all_params.
        _service.enable_retries()
        self.test_post_import_token_all_params()

        # Disable retries and run test_post_import_token_all_params.
        _service.disable_retries()
        self.test_post_import_token_all_params()

    @responses.activate
    def test_post_import_token_required_params(self):
        """
        test_post_import_token_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/import_token")
        mock_response = '{"expiration": 600, "maxAllowedRetrievals": 1, "creationDate": "2000-03-21T00:00:00.000Z", "expirationDate": "2000-03-21T00:00:00.000Z", "remainingRetrievals": 1}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Invoke method
        response = _service.post_import_token(
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_post_import_token_required_params_with_retries(self):
        # Enable retries and run test_post_import_token_required_params.
        _service.enable_retries()
        self.test_post_import_token_required_params()

        # Disable retries and run test_post_import_token_required_params.
        _service.disable_retries()
        self.test_post_import_token_required_params()

    @responses.activate
    def test_post_import_token_value_error(self):
        """
        test_post_import_token_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/import_token")
        mock_response = '{"expiration": 600, "maxAllowedRetrievals": 1, "creationDate": "2000-03-21T00:00:00.000Z", "expirationDate": "2000-03-21T00:00:00.000Z", "remainingRetrievals": 1}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.post_import_token(**req_copy)

    def test_post_import_token_value_error_with_retries(self):
        # Enable retries and run test_post_import_token_value_error.
        _service.enable_retries()
        self.test_post_import_token_value_error()

        # Disable retries and run test_post_import_token_value_error.
        _service.disable_retries()
        self.test_post_import_token_value_error()


class TestGetImportToken:
    """
    Test Class for get_import_token
    """

    @responses.activate
    def test_get_import_token_all_params(self):
        """
        get_import_token()
        """
        # Set up mock
        url = preprocess_url("/api/v2/import_token")
        mock_response = '{"expiration": 600, "maxAllowedRetrievals": 1, "creationDate": "2000-03-21T00:00:00.000Z", "expirationDate": "2000-03-21T00:00:00.000Z", "remainingRetrievals": 1, "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4=", "nonce": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "default"

        # Invoke method
        response = _service.get_import_token(
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_import_token_all_params_with_retries(self):
        # Enable retries and run test_get_import_token_all_params.
        _service.enable_retries()
        self.test_get_import_token_all_params()

        # Disable retries and run test_get_import_token_all_params.
        _service.disable_retries()
        self.test_get_import_token_all_params()

    @responses.activate
    def test_get_import_token_required_params(self):
        """
        test_get_import_token_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/import_token")
        mock_response = '{"expiration": 600, "maxAllowedRetrievals": 1, "creationDate": "2000-03-21T00:00:00.000Z", "expirationDate": "2000-03-21T00:00:00.000Z", "remainingRetrievals": 1, "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4=", "nonce": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_import_token(
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_import_token_required_params_with_retries(self):
        # Enable retries and run test_get_import_token_required_params.
        _service.enable_retries()
        self.test_get_import_token_required_params()

        # Disable retries and run test_get_import_token_required_params.
        _service.disable_retries()
        self.test_get_import_token_required_params()

    @responses.activate
    def test_get_import_token_value_error(self):
        """
        test_get_import_token_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/import_token")
        mock_response = '{"expiration": 600, "maxAllowedRetrievals": 1, "creationDate": "2000-03-21T00:00:00.000Z", "expirationDate": "2000-03-21T00:00:00.000Z", "remainingRetrievals": 1, "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4=", "nonce": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_import_token(**req_copy)

    def test_get_import_token_value_error_with_retries(self):
        # Enable retries and run test_get_import_token_value_error.
        _service.enable_retries()
        self.test_get_import_token_value_error()

        # Disable retries and run test_get_import_token_value_error.
        _service.disable_retries()
        self.test_get_import_token_value_error()


# endregion
##############################################################################
# End of Service: ImportTokens
##############################################################################

##############################################################################
# Start of Service: Registrations
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ["TEST_SERVICE_AUTH_TYPE"] = "noAuth"

        service = IbmKeyProtectApiV2.new_instance(
            service_name="TEST_SERVICE",
        )

        assert service is not None
        assert isinstance(service, IbmKeyProtectApiV2)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match="authenticator must be provided"):
            service = IbmKeyProtectApiV2.new_instance(
                service_name="TEST_SERVICE_NOT_FOUND",
            )


class TestGetRegistrations:
    """
    Test Class for get_registrations
    """

    @responses.activate
    def test_get_registrations_all_params(self):
        """
        get_registrations()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/registrations")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"keyId": "fadedbee-0000-0000-0000-1234567890ab", "keyName": "Example Key Name", "resourceCrn": "crn:v1:bluemix:public:<service-name>:<location>:a/<account-id>:<service-instance>:<resource-type>:<resource>", "createdBy": "IBMid-0000000000", "creationDate": "2000-03-21T00:00:00.000Z", "updatedBy": "IBMid-0000000000", "lastUpdated": "2000-03-21T00:00:00.000Z", "description": "Example description", "registrationMetadata": "us-south", "preventKeyDeletion": false, "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"
        limit = 200
        offset = 0
        url_encoded_resource_crn_query = "crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*"
        prevent_key_deletion = True
        total_count = True

        # Invoke method
        response = _service.get_registrations(
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            limit=limit,
            offset=offset,
            url_encoded_resource_crn_query=url_encoded_resource_crn_query,
            prevent_key_deletion=prevent_key_deletion,
            total_count=total_count,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "limit={}".format(limit) in query_string
        assert "offset={}".format(offset) in query_string
        assert "urlEncodedResourceCRNQuery={}".format(url_encoded_resource_crn_query) in query_string
        assert "preventKeyDeletion={}".format("true" if prevent_key_deletion else "false") in query_string
        assert "totalCount={}".format("true" if total_count else "false") in query_string

    def test_get_registrations_all_params_with_retries(self):
        # Enable retries and run test_get_registrations_all_params.
        _service.enable_retries()
        self.test_get_registrations_all_params()

        # Disable retries and run test_get_registrations_all_params.
        _service.disable_retries()
        self.test_get_registrations_all_params()

    @responses.activate
    def test_get_registrations_required_params(self):
        """
        test_get_registrations_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/registrations")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"keyId": "fadedbee-0000-0000-0000-1234567890ab", "keyName": "Example Key Name", "resourceCrn": "crn:v1:bluemix:public:<service-name>:<location>:a/<account-id>:<service-instance>:<resource-type>:<resource>", "createdBy": "IBMid-0000000000", "creationDate": "2000-03-21T00:00:00.000Z", "updatedBy": "IBMid-0000000000", "lastUpdated": "2000-03-21T00:00:00.000Z", "description": "Example description", "registrationMetadata": "us-south", "preventKeyDeletion": false, "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_registrations(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_registrations_required_params_with_retries(self):
        # Enable retries and run test_get_registrations_required_params.
        _service.enable_retries()
        self.test_get_registrations_required_params()

        # Disable retries and run test_get_registrations_required_params.
        _service.disable_retries()
        self.test_get_registrations_required_params()

    @responses.activate
    def test_get_registrations_value_error(self):
        """
        test_get_registrations_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/registrations")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"keyId": "fadedbee-0000-0000-0000-1234567890ab", "keyName": "Example Key Name", "resourceCrn": "crn:v1:bluemix:public:<service-name>:<location>:a/<account-id>:<service-instance>:<resource-type>:<resource>", "createdBy": "IBMid-0000000000", "creationDate": "2000-03-21T00:00:00.000Z", "updatedBy": "IBMid-0000000000", "lastUpdated": "2000-03-21T00:00:00.000Z", "description": "Example description", "registrationMetadata": "us-south", "preventKeyDeletion": false, "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_registrations(**req_copy)

    def test_get_registrations_value_error_with_retries(self):
        # Enable retries and run test_get_registrations_value_error.
        _service.enable_retries()
        self.test_get_registrations_value_error()

        # Disable retries and run test_get_registrations_value_error.
        _service.disable_retries()
        self.test_get_registrations_value_error()


class TestGetRegistrationsAllKeys:
    """
    Test Class for get_registrations_all_keys
    """

    @responses.activate
    def test_get_registrations_all_keys_all_params(self):
        """
        get_registrations_all_keys()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/registrations")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"keyId": "fadedbee-0000-0000-0000-1234567890ab", "keyName": "Example Key Name", "resourceCrn": "crn:v1:bluemix:public:<service-name>:<location>:a/<account-id>:<service-instance>:<resource-type>:<resource>", "createdBy": "IBMid-0000000000", "creationDate": "2000-03-21T00:00:00.000Z", "updatedBy": "IBMid-0000000000", "lastUpdated": "2000-03-21T00:00:00.000Z", "description": "Example description", "registrationMetadata": "us-south", "preventKeyDeletion": false, "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"
        url_encoded_resource_crn_query = "crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*"
        limit = 200
        offset = 0
        prevent_key_deletion = True
        total_count = True

        # Invoke method
        response = _service.get_registrations_all_keys(
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            url_encoded_resource_crn_query=url_encoded_resource_crn_query,
            limit=limit,
            offset=offset,
            prevent_key_deletion=prevent_key_deletion,
            total_count=total_count,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "urlEncodedResourceCRNQuery={}".format(url_encoded_resource_crn_query) in query_string
        assert "limit={}".format(limit) in query_string
        assert "offset={}".format(offset) in query_string
        assert "preventKeyDeletion={}".format("true" if prevent_key_deletion else "false") in query_string
        assert "totalCount={}".format("true" if total_count else "false") in query_string

    def test_get_registrations_all_keys_all_params_with_retries(self):
        # Enable retries and run test_get_registrations_all_keys_all_params.
        _service.enable_retries()
        self.test_get_registrations_all_keys_all_params()

        # Disable retries and run test_get_registrations_all_keys_all_params.
        _service.disable_retries()
        self.test_get_registrations_all_keys_all_params()

    @responses.activate
    def test_get_registrations_all_keys_required_params(self):
        """
        test_get_registrations_all_keys_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/registrations")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"keyId": "fadedbee-0000-0000-0000-1234567890ab", "keyName": "Example Key Name", "resourceCrn": "crn:v1:bluemix:public:<service-name>:<location>:a/<account-id>:<service-instance>:<resource-type>:<resource>", "createdBy": "IBMid-0000000000", "creationDate": "2000-03-21T00:00:00.000Z", "updatedBy": "IBMid-0000000000", "lastUpdated": "2000-03-21T00:00:00.000Z", "description": "Example description", "registrationMetadata": "us-south", "preventKeyDeletion": false, "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_registrations_all_keys(
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_registrations_all_keys_required_params_with_retries(self):
        # Enable retries and run test_get_registrations_all_keys_required_params.
        _service.enable_retries()
        self.test_get_registrations_all_keys_required_params()

        # Disable retries and run test_get_registrations_all_keys_required_params.
        _service.disable_retries()
        self.test_get_registrations_all_keys_required_params()

    @responses.activate
    def test_get_registrations_all_keys_value_error(self):
        """
        test_get_registrations_all_keys_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/registrations")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"keyId": "fadedbee-0000-0000-0000-1234567890ab", "keyName": "Example Key Name", "resourceCrn": "crn:v1:bluemix:public:<service-name>:<location>:a/<account-id>:<service-instance>:<resource-type>:<resource>", "createdBy": "IBMid-0000000000", "creationDate": "2000-03-21T00:00:00.000Z", "updatedBy": "IBMid-0000000000", "lastUpdated": "2000-03-21T00:00:00.000Z", "description": "Example description", "registrationMetadata": "us-south", "preventKeyDeletion": false, "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_registrations_all_keys(**req_copy)

    def test_get_registrations_all_keys_value_error_with_retries(self):
        # Enable retries and run test_get_registrations_all_keys_value_error.
        _service.enable_retries()
        self.test_get_registrations_all_keys_value_error()

        # Disable retries and run test_get_registrations_all_keys_value_error.
        _service.disable_retries()
        self.test_get_registrations_all_keys_value_error()


# endregion
##############################################################################
# End of Service: Registrations
##############################################################################

##############################################################################
# Start of Service: Aliases
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ["TEST_SERVICE_AUTH_TYPE"] = "noAuth"

        service = IbmKeyProtectApiV2.new_instance(
            service_name="TEST_SERVICE",
        )

        assert service is not None
        assert isinstance(service, IbmKeyProtectApiV2)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match="authenticator must be provided"):
            service = IbmKeyProtectApiV2.new_instance(
                service_name="TEST_SERVICE_NOT_FOUND",
            )


class TestCreateKeyAlias:
    """
    Test Class for create_key_alias
    """

    @responses.activate
    def test_create_key_alias_all_params(self):
        """
        create_key_alias()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/aliases/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"keyId": "fadedbee-0000-0000-0000-1234567890ab", "alias": "Example-test-key", "createdBy": "IBMid-0000000000", "creationDate": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        alias = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"

        # Invoke method
        response = _service.create_key_alias(
            id,
            alias,
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_create_key_alias_all_params_with_retries(self):
        # Enable retries and run test_create_key_alias_all_params.
        _service.enable_retries()
        self.test_create_key_alias_all_params()

        # Disable retries and run test_create_key_alias_all_params.
        _service.disable_retries()
        self.test_create_key_alias_all_params()

    @responses.activate
    def test_create_key_alias_required_params(self):
        """
        test_create_key_alias_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/aliases/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"keyId": "fadedbee-0000-0000-0000-1234567890ab", "alias": "Example-test-key", "createdBy": "IBMid-0000000000", "creationDate": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        alias = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.create_key_alias(
            id,
            alias,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_create_key_alias_required_params_with_retries(self):
        # Enable retries and run test_create_key_alias_required_params.
        _service.enable_retries()
        self.test_create_key_alias_required_params()

        # Disable retries and run test_create_key_alias_required_params.
        _service.disable_retries()
        self.test_create_key_alias_required_params()

    @responses.activate
    def test_create_key_alias_value_error(self):
        """
        test_create_key_alias_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/aliases/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"keyId": "fadedbee-0000-0000-0000-1234567890ab", "alias": "Example-test-key", "createdBy": "IBMid-0000000000", "creationDate": "2000-03-21T00:00:00.000Z"}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        alias = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "alias": alias,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_key_alias(**req_copy)

    def test_create_key_alias_value_error_with_retries(self):
        # Enable retries and run test_create_key_alias_value_error.
        _service.enable_retries()
        self.test_create_key_alias_value_error()

        # Disable retries and run test_create_key_alias_value_error.
        _service.disable_retries()
        self.test_create_key_alias_value_error()


class TestDeleteKeyAlias:
    """
    Test Class for delete_key_alias
    """

    @responses.activate
    def test_delete_key_alias_all_params(self):
        """
        delete_key_alias()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/aliases/testString")
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        alias = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        x_kms_key_ring = "testString"

        # Invoke method
        response = _service.delete_key_alias(
            id,
            alias,
            bluemix_instance,
            correlation_id=correlation_id,
            x_kms_key_ring=x_kms_key_ring,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_key_alias_all_params_with_retries(self):
        # Enable retries and run test_delete_key_alias_all_params.
        _service.enable_retries()
        self.test_delete_key_alias_all_params()

        # Disable retries and run test_delete_key_alias_all_params.
        _service.disable_retries()
        self.test_delete_key_alias_all_params()

    @responses.activate
    def test_delete_key_alias_required_params(self):
        """
        test_delete_key_alias_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/aliases/testString")
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        alias = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.delete_key_alias(
            id,
            alias,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_key_alias_required_params_with_retries(self):
        # Enable retries and run test_delete_key_alias_required_params.
        _service.enable_retries()
        self.test_delete_key_alias_required_params()

        # Disable retries and run test_delete_key_alias_required_params.
        _service.disable_retries()
        self.test_delete_key_alias_required_params()

    @responses.activate
    def test_delete_key_alias_value_error(self):
        """
        test_delete_key_alias_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/keys/testString/aliases/testString")
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        alias = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "alias": alias,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_key_alias(**req_copy)

    def test_delete_key_alias_value_error_with_retries(self):
        # Enable retries and run test_delete_key_alias_value_error.
        _service.enable_retries()
        self.test_delete_key_alias_value_error()

        # Disable retries and run test_delete_key_alias_value_error.
        _service.disable_retries()
        self.test_delete_key_alias_value_error()


# endregion
##############################################################################
# End of Service: Aliases
##############################################################################

##############################################################################
# Start of Service: KeyRings
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ["TEST_SERVICE_AUTH_TYPE"] = "noAuth"

        service = IbmKeyProtectApiV2.new_instance(
            service_name="TEST_SERVICE",
        )

        assert service is not None
        assert isinstance(service, IbmKeyProtectApiV2)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match="authenticator must be provided"):
            service = IbmKeyProtectApiV2.new_instance(
                service_name="TEST_SERVICE_NOT_FOUND",
            )


class TestListKeyRings:
    """
    Test Class for list_key_rings
    """

    @responses.activate
    def test_list_key_rings_all_params(self):
        """
        list_key_rings()
        """
        # Set up mock
        url = preprocess_url("/api/v2/key_rings")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"
        limit = 100
        offset = 0
        total_count = True
        correlation_id = "testString"

        # Invoke method
        response = _service.list_key_rings(
            bluemix_instance,
            limit=limit,
            offset=offset,
            total_count=total_count,
            correlation_id=correlation_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "limit={}".format(limit) in query_string
        assert "offset={}".format(offset) in query_string
        assert "totalCount={}".format("true" if total_count else "false") in query_string

    def test_list_key_rings_all_params_with_retries(self):
        # Enable retries and run test_list_key_rings_all_params.
        _service.enable_retries()
        self.test_list_key_rings_all_params()

        # Disable retries and run test_list_key_rings_all_params.
        _service.disable_retries()
        self.test_list_key_rings_all_params()

    @responses.activate
    def test_list_key_rings_required_params(self):
        """
        test_list_key_rings_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/key_rings")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Invoke method
        response = _service.list_key_rings(
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_list_key_rings_required_params_with_retries(self):
        # Enable retries and run test_list_key_rings_required_params.
        _service.enable_retries()
        self.test_list_key_rings_required_params()

        # Disable retries and run test_list_key_rings_required_params.
        _service.disable_retries()
        self.test_list_key_rings_required_params()

    @responses.activate
    def test_list_key_rings_value_error(self):
        """
        test_list_key_rings_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/key_rings")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "id", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "created_by"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.list_key_rings(**req_copy)

    def test_list_key_rings_value_error_with_retries(self):
        # Enable retries and run test_list_key_rings_value_error.
        _service.enable_retries()
        self.test_list_key_rings_value_error()

        # Disable retries and run test_list_key_rings_value_error.
        _service.disable_retries()
        self.test_list_key_rings_value_error()


class TestCreateKeyRing:
    """
    Test Class for create_key_ring
    """

    @responses.activate
    def test_create_key_ring_all_params(self):
        """
        create_key_ring()
        """
        # Set up mock
        url = preprocess_url("/api/v2/key_rings/testString")
        responses.add(
            responses.POST,
            url,
            status=201,
        )

        # Set up parameter values
        key_ring_id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"

        # Invoke method
        response = _service.create_key_ring(
            key_ring_id,
            bluemix_instance,
            correlation_id=correlation_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201

    def test_create_key_ring_all_params_with_retries(self):
        # Enable retries and run test_create_key_ring_all_params.
        _service.enable_retries()
        self.test_create_key_ring_all_params()

        # Disable retries and run test_create_key_ring_all_params.
        _service.disable_retries()
        self.test_create_key_ring_all_params()

    @responses.activate
    def test_create_key_ring_required_params(self):
        """
        test_create_key_ring_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/key_rings/testString")
        responses.add(
            responses.POST,
            url,
            status=201,
        )

        # Set up parameter values
        key_ring_id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.create_key_ring(
            key_ring_id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201

    def test_create_key_ring_required_params_with_retries(self):
        # Enable retries and run test_create_key_ring_required_params.
        _service.enable_retries()
        self.test_create_key_ring_required_params()

        # Disable retries and run test_create_key_ring_required_params.
        _service.disable_retries()
        self.test_create_key_ring_required_params()

    @responses.activate
    def test_create_key_ring_value_error(self):
        """
        test_create_key_ring_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/key_rings/testString")
        responses.add(
            responses.POST,
            url,
            status=201,
        )

        # Set up parameter values
        key_ring_id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "key_ring_id": key_ring_id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_key_ring(**req_copy)

    def test_create_key_ring_value_error_with_retries(self):
        # Enable retries and run test_create_key_ring_value_error.
        _service.enable_retries()
        self.test_create_key_ring_value_error()

        # Disable retries and run test_create_key_ring_value_error.
        _service.disable_retries()
        self.test_create_key_ring_value_error()


class TestDeleteKeyRing:
    """
    Test Class for delete_key_ring
    """

    @responses.activate
    def test_delete_key_ring_all_params(self):
        """
        delete_key_ring()
        """
        # Set up mock
        url = preprocess_url("/api/v2/key_rings/testString")
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        key_ring_id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"
        force = False

        # Invoke method
        response = _service.delete_key_ring(
            key_ring_id,
            bluemix_instance,
            correlation_id=correlation_id,
            force=force,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "force={}".format("true" if force else "false") in query_string

    def test_delete_key_ring_all_params_with_retries(self):
        # Enable retries and run test_delete_key_ring_all_params.
        _service.enable_retries()
        self.test_delete_key_ring_all_params()

        # Disable retries and run test_delete_key_ring_all_params.
        _service.disable_retries()
        self.test_delete_key_ring_all_params()

    @responses.activate
    def test_delete_key_ring_required_params(self):
        """
        test_delete_key_ring_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/key_rings/testString")
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        key_ring_id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.delete_key_ring(
            key_ring_id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_key_ring_required_params_with_retries(self):
        # Enable retries and run test_delete_key_ring_required_params.
        _service.enable_retries()
        self.test_delete_key_ring_required_params()

        # Disable retries and run test_delete_key_ring_required_params.
        _service.disable_retries()
        self.test_delete_key_ring_required_params()

    @responses.activate
    def test_delete_key_ring_value_error(self):
        """
        test_delete_key_ring_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/key_rings/testString")
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        key_ring_id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "key_ring_id": key_ring_id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_key_ring(**req_copy)

    def test_delete_key_ring_value_error_with_retries(self):
        # Enable retries and run test_delete_key_ring_value_error.
        _service.enable_retries()
        self.test_delete_key_ring_value_error()

        # Disable retries and run test_delete_key_ring_value_error.
        _service.disable_retries()
        self.test_delete_key_ring_value_error()


# endregion
##############################################################################
# End of Service: KeyRings
##############################################################################

##############################################################################
# Start of Service: KMIPAdapters
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ["TEST_SERVICE_AUTH_TYPE"] = "noAuth"

        service = IbmKeyProtectApiV2.new_instance(
            service_name="TEST_SERVICE",
        )

        assert service is not None
        assert isinstance(service, IbmKeyProtectApiV2)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match="authenticator must be provided"):
            service = IbmKeyProtectApiV2.new_instance(
                service_name="TEST_SERVICE_NOT_FOUND",
            )


class TestGetKmipAdapters:
    """
    Test Class for get_kmip_adapters
    """

    @responses.activate
    def test_get_kmip_adapters_all_params(self):
        """
        get_kmip_adapters()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "name": "kmip-adapter-name", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "profile": "native_1.0", "description": "kmip adapter description", "profile_data": {"crk_id": "feddecaf-0000-0000-0000-1234567890ab"}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"
        correlation_id = "testString"
        limit = 100
        offset = 0
        total_count = True
        crk_id = "feddecaf-0000-0000-0000-1234567890ab"

        # Invoke method
        response = _service.get_kmip_adapters(
            bluemix_instance,
            correlation_id=correlation_id,
            limit=limit,
            offset=offset,
            total_count=total_count,
            crk_id=crk_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "limit={}".format(limit) in query_string
        assert "offset={}".format(offset) in query_string
        assert "totalCount={}".format("true" if total_count else "false") in query_string
        assert "crk_id={}".format(crk_id) in query_string

    def test_get_kmip_adapters_all_params_with_retries(self):
        # Enable retries and run test_get_kmip_adapters_all_params.
        _service.enable_retries()
        self.test_get_kmip_adapters_all_params()

        # Disable retries and run test_get_kmip_adapters_all_params.
        _service.disable_retries()
        self.test_get_kmip_adapters_all_params()

    @responses.activate
    def test_get_kmip_adapters_required_params(self):
        """
        test_get_kmip_adapters_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "name": "kmip-adapter-name", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "profile": "native_1.0", "description": "kmip adapter description", "profile_data": {"crk_id": "feddecaf-0000-0000-0000-1234567890ab"}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_kmip_adapters(
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_kmip_adapters_required_params_with_retries(self):
        # Enable retries and run test_get_kmip_adapters_required_params.
        _service.enable_retries()
        self.test_get_kmip_adapters_required_params()

        # Disable retries and run test_get_kmip_adapters_required_params.
        _service.disable_retries()
        self.test_get_kmip_adapters_required_params()

    @responses.activate
    def test_get_kmip_adapters_value_error(self):
        """
        test_get_kmip_adapters_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "name": "kmip-adapter-name", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "profile": "native_1.0", "description": "kmip adapter description", "profile_data": {"crk_id": "feddecaf-0000-0000-0000-1234567890ab"}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_kmip_adapters(**req_copy)

    def test_get_kmip_adapters_value_error_with_retries(self):
        # Enable retries and run test_get_kmip_adapters_value_error.
        _service.enable_retries()
        self.test_get_kmip_adapters_value_error()

        # Disable retries and run test_get_kmip_adapters_value_error.
        _service.disable_retries()
        self.test_get_kmip_adapters_value_error()


class TestCreateKmipAdapter:
    """
    Test Class for create_kmip_adapter
    """

    @responses.activate
    def test_create_kmip_adapter_all_params(self):
        """
        create_kmip_adapter()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "name": "kmip-adapter-name", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "profile": "native_1.0", "description": "kmip adapter description", "profile_data": {"crk_id": "feddecaf-0000-0000-0000-1234567890ab"}}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=201,
        )

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.kmip_adapter+json"
        collection_metadata_model["collectionTotal"] = 1

        # Construct a dict representation of a KMIPProfileDataBodyKMIPProfileDataNative model
        kmip_profile_data_body_model = {}
        kmip_profile_data_body_model["crk_id"] = "feddecaf-0000-0000-0000-1234567890ab"

        # Construct a dict representation of a CreateKMIPAdapterObject model
        create_kmip_adapter_object_model = {}
        create_kmip_adapter_object_model["name"] = "kmip-adapter-name"
        create_kmip_adapter_object_model["description"] = "kmip adapter description"
        create_kmip_adapter_object_model["profile"] = "native_1.0"
        create_kmip_adapter_object_model["profile_data"] = kmip_profile_data_body_model

        # Set up parameter values
        bluemix_instance = "testString"
        metadata = collection_metadata_model
        resources = [create_kmip_adapter_object_model]
        correlation_id = "testString"
        allow_expiring_key = True

        # Invoke method
        response = _service.create_kmip_adapter(
            bluemix_instance,
            metadata,
            resources,
            correlation_id=correlation_id,
            allow_expiring_key=allow_expiring_key,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "allowExpiringKey={}".format("true" if allow_expiring_key else "false") in query_string
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, "utf-8"))
        assert req_body["metadata"] == collection_metadata_model
        assert req_body["resources"] == [create_kmip_adapter_object_model]

    def test_create_kmip_adapter_all_params_with_retries(self):
        # Enable retries and run test_create_kmip_adapter_all_params.
        _service.enable_retries()
        self.test_create_kmip_adapter_all_params()

        # Disable retries and run test_create_kmip_adapter_all_params.
        _service.disable_retries()
        self.test_create_kmip_adapter_all_params()

    @responses.activate
    def test_create_kmip_adapter_required_params(self):
        """
        test_create_kmip_adapter_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "name": "kmip-adapter-name", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "profile": "native_1.0", "description": "kmip adapter description", "profile_data": {"crk_id": "feddecaf-0000-0000-0000-1234567890ab"}}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=201,
        )

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.kmip_adapter+json"
        collection_metadata_model["collectionTotal"] = 1

        # Construct a dict representation of a KMIPProfileDataBodyKMIPProfileDataNative model
        kmip_profile_data_body_model = {}
        kmip_profile_data_body_model["crk_id"] = "feddecaf-0000-0000-0000-1234567890ab"

        # Construct a dict representation of a CreateKMIPAdapterObject model
        create_kmip_adapter_object_model = {}
        create_kmip_adapter_object_model["name"] = "kmip-adapter-name"
        create_kmip_adapter_object_model["description"] = "kmip adapter description"
        create_kmip_adapter_object_model["profile"] = "native_1.0"
        create_kmip_adapter_object_model["profile_data"] = kmip_profile_data_body_model

        # Set up parameter values
        bluemix_instance = "testString"
        metadata = collection_metadata_model
        resources = [create_kmip_adapter_object_model]

        # Invoke method
        response = _service.create_kmip_adapter(
            bluemix_instance,
            metadata,
            resources,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, "utf-8"))
        assert req_body["metadata"] == collection_metadata_model
        assert req_body["resources"] == [create_kmip_adapter_object_model]

    def test_create_kmip_adapter_required_params_with_retries(self):
        # Enable retries and run test_create_kmip_adapter_required_params.
        _service.enable_retries()
        self.test_create_kmip_adapter_required_params()

        # Disable retries and run test_create_kmip_adapter_required_params.
        _service.disable_retries()
        self.test_create_kmip_adapter_required_params()

    @responses.activate
    def test_create_kmip_adapter_value_error(self):
        """
        test_create_kmip_adapter_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "name": "kmip-adapter-name", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "profile": "native_1.0", "description": "kmip adapter description", "profile_data": {"crk_id": "feddecaf-0000-0000-0000-1234567890ab"}}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=201,
        )

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.kmip_adapter+json"
        collection_metadata_model["collectionTotal"] = 1

        # Construct a dict representation of a KMIPProfileDataBodyKMIPProfileDataNative model
        kmip_profile_data_body_model = {}
        kmip_profile_data_body_model["crk_id"] = "feddecaf-0000-0000-0000-1234567890ab"

        # Construct a dict representation of a CreateKMIPAdapterObject model
        create_kmip_adapter_object_model = {}
        create_kmip_adapter_object_model["name"] = "kmip-adapter-name"
        create_kmip_adapter_object_model["description"] = "kmip adapter description"
        create_kmip_adapter_object_model["profile"] = "native_1.0"
        create_kmip_adapter_object_model["profile_data"] = kmip_profile_data_body_model

        # Set up parameter values
        bluemix_instance = "testString"
        metadata = collection_metadata_model
        resources = [create_kmip_adapter_object_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bluemix_instance": bluemix_instance,
            "metadata": metadata,
            "resources": resources,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_kmip_adapter(**req_copy)

    def test_create_kmip_adapter_value_error_with_retries(self):
        # Enable retries and run test_create_kmip_adapter_value_error.
        _service.enable_retries()
        self.test_create_kmip_adapter_value_error()

        # Disable retries and run test_create_kmip_adapter_value_error.
        _service.disable_retries()
        self.test_create_kmip_adapter_value_error()


class TestGetKmipAdapter:
    """
    Test Class for get_kmip_adapter
    """

    @responses.activate
    def test_get_kmip_adapter_all_params(self):
        """
        get_kmip_adapter()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "name": "kmip-adapter-name", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "profile": "native_1.0", "description": "kmip adapter description", "profile_data": {"crk_id": "feddecaf-0000-0000-0000-1234567890ab"}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"

        # Invoke method
        response = _service.get_kmip_adapter(
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_kmip_adapter_all_params_with_retries(self):
        # Enable retries and run test_get_kmip_adapter_all_params.
        _service.enable_retries()
        self.test_get_kmip_adapter_all_params()

        # Disable retries and run test_get_kmip_adapter_all_params.
        _service.disable_retries()
        self.test_get_kmip_adapter_all_params()

    @responses.activate
    def test_get_kmip_adapter_required_params(self):
        """
        test_get_kmip_adapter_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "name": "kmip-adapter-name", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "profile": "native_1.0", "description": "kmip adapter description", "profile_data": {"crk_id": "feddecaf-0000-0000-0000-1234567890ab"}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_kmip_adapter(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_kmip_adapter_required_params_with_retries(self):
        # Enable retries and run test_get_kmip_adapter_required_params.
        _service.enable_retries()
        self.test_get_kmip_adapter_required_params()

        # Disable retries and run test_get_kmip_adapter_required_params.
        _service.disable_retries()
        self.test_get_kmip_adapter_required_params()

    @responses.activate
    def test_get_kmip_adapter_value_error(self):
        """
        test_get_kmip_adapter_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "name": "kmip-adapter-name", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "profile": "native_1.0", "description": "kmip adapter description", "profile_data": {"crk_id": "feddecaf-0000-0000-0000-1234567890ab"}}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_kmip_adapter(**req_copy)

    def test_get_kmip_adapter_value_error_with_retries(self):
        # Enable retries and run test_get_kmip_adapter_value_error.
        _service.enable_retries()
        self.test_get_kmip_adapter_value_error()

        # Disable retries and run test_get_kmip_adapter_value_error.
        _service.disable_retries()
        self.test_get_kmip_adapter_value_error()


class TestDeleteKmipAdapter:
    """
    Test Class for delete_kmip_adapter
    """

    @responses.activate
    def test_delete_kmip_adapter_all_params(self):
        """
        delete_kmip_adapter()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString")
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"

        # Invoke method
        response = _service.delete_kmip_adapter(
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_kmip_adapter_all_params_with_retries(self):
        # Enable retries and run test_delete_kmip_adapter_all_params.
        _service.enable_retries()
        self.test_delete_kmip_adapter_all_params()

        # Disable retries and run test_delete_kmip_adapter_all_params.
        _service.disable_retries()
        self.test_delete_kmip_adapter_all_params()

    @responses.activate
    def test_delete_kmip_adapter_required_params(self):
        """
        test_delete_kmip_adapter_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString")
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.delete_kmip_adapter(
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_kmip_adapter_required_params_with_retries(self):
        # Enable retries and run test_delete_kmip_adapter_required_params.
        _service.enable_retries()
        self.test_delete_kmip_adapter_required_params()

        # Disable retries and run test_delete_kmip_adapter_required_params.
        _service.disable_retries()
        self.test_delete_kmip_adapter_required_params()

    @responses.activate
    def test_delete_kmip_adapter_value_error(self):
        """
        test_delete_kmip_adapter_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString")
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_kmip_adapter(**req_copy)

    def test_delete_kmip_adapter_value_error_with_retries(self):
        # Enable retries and run test_delete_kmip_adapter_value_error.
        _service.enable_retries()
        self.test_delete_kmip_adapter_value_error()

        # Disable retries and run test_delete_kmip_adapter_value_error.
        _service.disable_retries()
        self.test_delete_kmip_adapter_value_error()


class TestGetKmipObjects:
    """
    Test Class for get_kmip_objects
    """

    @responses.activate
    def test_get_kmip_objects_all_params(self):
        """
        get_kmip_objects()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/kmip_objects")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "kmip_object_type": 2, "state": 1, "created_at": "2019-01-01T12:00:00.000Z", "created_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "created_by": "created_by", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "updated_by": "updated_by", "destroyed_at": "2019-01-01T12:00:00.000Z", "destroyed_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "destroyed_by": "destroyed_by", "recoverable": false}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        adapter_id = "testString"
        bluemix_instance = "testString"
        limit = 100
        offset = 0
        total_count = True
        state = [1, 2, 3, 4]
        correlation_id = "testString"

        # Invoke method
        response = _service.get_kmip_objects(
            adapter_id,
            bluemix_instance,
            limit=limit,
            offset=offset,
            total_count=total_count,
            state=state,
            correlation_id=correlation_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "limit={}".format(limit) in query_string
        assert "offset={}".format(offset) in query_string
        assert "totalCount={}".format("true" if total_count else "false") in query_string
        assert "state={}".format(",".join([str(x) for x in state])) in query_string

    def test_get_kmip_objects_all_params_with_retries(self):
        # Enable retries and run test_get_kmip_objects_all_params.
        _service.enable_retries()
        self.test_get_kmip_objects_all_params()

        # Disable retries and run test_get_kmip_objects_all_params.
        _service.disable_retries()
        self.test_get_kmip_objects_all_params()

    @responses.activate
    def test_get_kmip_objects_required_params(self):
        """
        test_get_kmip_objects_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/kmip_objects")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "kmip_object_type": 2, "state": 1, "created_at": "2019-01-01T12:00:00.000Z", "created_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "created_by": "created_by", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "updated_by": "updated_by", "destroyed_at": "2019-01-01T12:00:00.000Z", "destroyed_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "destroyed_by": "destroyed_by", "recoverable": false}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        adapter_id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_kmip_objects(
            adapter_id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_kmip_objects_required_params_with_retries(self):
        # Enable retries and run test_get_kmip_objects_required_params.
        _service.enable_retries()
        self.test_get_kmip_objects_required_params()

        # Disable retries and run test_get_kmip_objects_required_params.
        _service.disable_retries()
        self.test_get_kmip_objects_required_params()

    @responses.activate
    def test_get_kmip_objects_value_error(self):
        """
        test_get_kmip_objects_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/kmip_objects")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "kmip_object_type": 2, "state": 1, "created_at": "2019-01-01T12:00:00.000Z", "created_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "created_by": "created_by", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "updated_by": "updated_by", "destroyed_at": "2019-01-01T12:00:00.000Z", "destroyed_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "destroyed_by": "destroyed_by", "recoverable": false}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        adapter_id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "adapter_id": adapter_id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_kmip_objects(**req_copy)

    def test_get_kmip_objects_value_error_with_retries(self):
        # Enable retries and run test_get_kmip_objects_value_error.
        _service.enable_retries()
        self.test_get_kmip_objects_value_error()

        # Disable retries and run test_get_kmip_objects_value_error.
        _service.disable_retries()
        self.test_get_kmip_objects_value_error()


class TestGetKmipObject:
    """
    Test Class for get_kmip_object
    """

    @responses.activate
    def test_get_kmip_object_all_params(self):
        """
        get_kmip_object()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/kmip_objects/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "kmip_object_type": 2, "state": 1, "created_at": "2019-01-01T12:00:00.000Z", "created_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "created_by": "created_by", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "updated_by": "updated_by", "destroyed_at": "2019-01-01T12:00:00.000Z", "destroyed_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "destroyed_by": "destroyed_by", "recoverable": false}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        adapter_id = "testString"
        bluemix_instance = "testString"
        id = "testString"
        correlation_id = "testString"

        # Invoke method
        response = _service.get_kmip_object(
            adapter_id,
            bluemix_instance,
            id,
            correlation_id=correlation_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_kmip_object_all_params_with_retries(self):
        # Enable retries and run test_get_kmip_object_all_params.
        _service.enable_retries()
        self.test_get_kmip_object_all_params()

        # Disable retries and run test_get_kmip_object_all_params.
        _service.disable_retries()
        self.test_get_kmip_object_all_params()

    @responses.activate
    def test_get_kmip_object_required_params(self):
        """
        test_get_kmip_object_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/kmip_objects/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "kmip_object_type": 2, "state": 1, "created_at": "2019-01-01T12:00:00.000Z", "created_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "created_by": "created_by", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "updated_by": "updated_by", "destroyed_at": "2019-01-01T12:00:00.000Z", "destroyed_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "destroyed_by": "destroyed_by", "recoverable": false}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        adapter_id = "testString"
        bluemix_instance = "testString"
        id = "testString"

        # Invoke method
        response = _service.get_kmip_object(
            adapter_id,
            bluemix_instance,
            id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_kmip_object_required_params_with_retries(self):
        # Enable retries and run test_get_kmip_object_required_params.
        _service.enable_retries()
        self.test_get_kmip_object_required_params()

        # Disable retries and run test_get_kmip_object_required_params.
        _service.disable_retries()
        self.test_get_kmip_object_required_params()

    @responses.activate
    def test_get_kmip_object_value_error(self):
        """
        test_get_kmip_object_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/kmip_objects/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "kmip_object_type": 2, "state": 1, "created_at": "2019-01-01T12:00:00.000Z", "created_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "created_by": "created_by", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "updated_by": "updated_by", "destroyed_at": "2019-01-01T12:00:00.000Z", "destroyed_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "destroyed_by": "destroyed_by", "recoverable": false}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        adapter_id = "testString"
        bluemix_instance = "testString"
        id = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "adapter_id": adapter_id,
            "bluemix_instance": bluemix_instance,
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_kmip_object(**req_copy)

    def test_get_kmip_object_value_error_with_retries(self):
        # Enable retries and run test_get_kmip_object_value_error.
        _service.enable_retries()
        self.test_get_kmip_object_value_error()

        # Disable retries and run test_get_kmip_object_value_error.
        _service.disable_retries()
        self.test_get_kmip_object_value_error()


class TestDeleteKmipObject:
    """
    Test Class for delete_kmip_object
    """

    @responses.activate
    def test_delete_kmip_object_all_params(self):
        """
        delete_kmip_object()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/kmip_objects/testString")
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        adapter_id = "testString"
        bluemix_instance = "testString"
        id = "testString"
        correlation_id = "testString"
        force = False

        # Invoke method
        response = _service.delete_kmip_object(
            adapter_id,
            bluemix_instance,
            id,
            correlation_id=correlation_id,
            force=force,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "force={}".format("true" if force else "false") in query_string

    def test_delete_kmip_object_all_params_with_retries(self):
        # Enable retries and run test_delete_kmip_object_all_params.
        _service.enable_retries()
        self.test_delete_kmip_object_all_params()

        # Disable retries and run test_delete_kmip_object_all_params.
        _service.disable_retries()
        self.test_delete_kmip_object_all_params()

    @responses.activate
    def test_delete_kmip_object_required_params(self):
        """
        test_delete_kmip_object_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/kmip_objects/testString")
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        adapter_id = "testString"
        bluemix_instance = "testString"
        id = "testString"

        # Invoke method
        response = _service.delete_kmip_object(
            adapter_id,
            bluemix_instance,
            id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_kmip_object_required_params_with_retries(self):
        # Enable retries and run test_delete_kmip_object_required_params.
        _service.enable_retries()
        self.test_delete_kmip_object_required_params()

        # Disable retries and run test_delete_kmip_object_required_params.
        _service.disable_retries()
        self.test_delete_kmip_object_required_params()

    @responses.activate
    def test_delete_kmip_object_value_error(self):
        """
        test_delete_kmip_object_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/kmip_objects/testString")
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        adapter_id = "testString"
        bluemix_instance = "testString"
        id = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "adapter_id": adapter_id,
            "bluemix_instance": bluemix_instance,
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_kmip_object(**req_copy)

    def test_delete_kmip_object_value_error_with_retries(self):
        # Enable retries and run test_delete_kmip_object_value_error.
        _service.enable_retries()
        self.test_delete_kmip_object_value_error()

        # Disable retries and run test_delete_kmip_object_value_error.
        _service.disable_retries()
        self.test_delete_kmip_object_value_error()


class TestGetKmipClientCertificates:
    """
    Test Class for get_kmip_client_certificates
    """

    @responses.activate
    def test_get_kmip_client_certificates_all_params(self):
        """
        get_kmip_client_certificates()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/certificates")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"name": "name", "id": "feddecaf-0000-0000-0000-1234567890ab", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        adapter_id = "testString"
        bluemix_instance = "testString"
        limit = 100
        offset = 0
        total_count = True
        correlation_id = "testString"

        # Invoke method
        response = _service.get_kmip_client_certificates(
            adapter_id,
            bluemix_instance,
            limit=limit,
            offset=offset,
            total_count=total_count,
            correlation_id=correlation_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split("?", 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert "limit={}".format(limit) in query_string
        assert "offset={}".format(offset) in query_string
        assert "totalCount={}".format("true" if total_count else "false") in query_string

    def test_get_kmip_client_certificates_all_params_with_retries(self):
        # Enable retries and run test_get_kmip_client_certificates_all_params.
        _service.enable_retries()
        self.test_get_kmip_client_certificates_all_params()

        # Disable retries and run test_get_kmip_client_certificates_all_params.
        _service.disable_retries()
        self.test_get_kmip_client_certificates_all_params()

    @responses.activate
    def test_get_kmip_client_certificates_required_params(self):
        """
        test_get_kmip_client_certificates_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/certificates")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"name": "name", "id": "feddecaf-0000-0000-0000-1234567890ab", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        adapter_id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_kmip_client_certificates(
            adapter_id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_kmip_client_certificates_required_params_with_retries(self):
        # Enable retries and run test_get_kmip_client_certificates_required_params.
        _service.enable_retries()
        self.test_get_kmip_client_certificates_required_params()

        # Disable retries and run test_get_kmip_client_certificates_required_params.
        _service.disable_retries()
        self.test_get_kmip_client_certificates_required_params()

    @responses.activate
    def test_get_kmip_client_certificates_value_error(self):
        """
        test_get_kmip_client_certificates_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/certificates")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"name": "name", "id": "feddecaf-0000-0000-0000-1234567890ab", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        adapter_id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "adapter_id": adapter_id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_kmip_client_certificates(**req_copy)

    def test_get_kmip_client_certificates_value_error_with_retries(self):
        # Enable retries and run test_get_kmip_client_certificates_value_error.
        _service.enable_retries()
        self.test_get_kmip_client_certificates_value_error()

        # Disable retries and run test_get_kmip_client_certificates_value_error.
        _service.disable_retries()
        self.test_get_kmip_client_certificates_value_error()


class TestAddKmipClientCertificate:
    """
    Test Class for add_kmip_client_certificate
    """

    @responses.activate
    def test_add_kmip_client_certificate_all_params(self):
        """
        add_kmip_client_certificate()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/certificates")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"name": "name", "id": "feddecaf-0000-0000-0000-1234567890ab", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "certificate": "certificate"}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=201,
        )

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.kmip_client_certificate+json"
        collection_metadata_model["collectionTotal"] = 1

        # Construct a dict representation of a CreateKMIPClientCertificateObject model
        create_kmip_client_certificate_object_model = {}
        create_kmip_client_certificate_object_model["certificate"] = "testString"
        create_kmip_client_certificate_object_model["name"] = "testString"

        # Set up parameter values
        adapter_id = "testString"
        bluemix_instance = "testString"
        metadata = collection_metadata_model
        resources = [create_kmip_client_certificate_object_model]
        correlation_id = "testString"

        # Invoke method
        response = _service.add_kmip_client_certificate(
            adapter_id,
            bluemix_instance,
            metadata,
            resources,
            correlation_id=correlation_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, "utf-8"))
        assert req_body["metadata"] == collection_metadata_model
        assert req_body["resources"] == [create_kmip_client_certificate_object_model]

    def test_add_kmip_client_certificate_all_params_with_retries(self):
        # Enable retries and run test_add_kmip_client_certificate_all_params.
        _service.enable_retries()
        self.test_add_kmip_client_certificate_all_params()

        # Disable retries and run test_add_kmip_client_certificate_all_params.
        _service.disable_retries()
        self.test_add_kmip_client_certificate_all_params()

    @responses.activate
    def test_add_kmip_client_certificate_required_params(self):
        """
        test_add_kmip_client_certificate_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/certificates")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"name": "name", "id": "feddecaf-0000-0000-0000-1234567890ab", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "certificate": "certificate"}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=201,
        )

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.kmip_client_certificate+json"
        collection_metadata_model["collectionTotal"] = 1

        # Construct a dict representation of a CreateKMIPClientCertificateObject model
        create_kmip_client_certificate_object_model = {}
        create_kmip_client_certificate_object_model["certificate"] = "testString"
        create_kmip_client_certificate_object_model["name"] = "testString"

        # Set up parameter values
        adapter_id = "testString"
        bluemix_instance = "testString"
        metadata = collection_metadata_model
        resources = [create_kmip_client_certificate_object_model]

        # Invoke method
        response = _service.add_kmip_client_certificate(
            adapter_id,
            bluemix_instance,
            metadata,
            resources,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, "utf-8"))
        assert req_body["metadata"] == collection_metadata_model
        assert req_body["resources"] == [create_kmip_client_certificate_object_model]

    def test_add_kmip_client_certificate_required_params_with_retries(self):
        # Enable retries and run test_add_kmip_client_certificate_required_params.
        _service.enable_retries()
        self.test_add_kmip_client_certificate_required_params()

        # Disable retries and run test_add_kmip_client_certificate_required_params.
        _service.disable_retries()
        self.test_add_kmip_client_certificate_required_params()

    @responses.activate
    def test_add_kmip_client_certificate_value_error(self):
        """
        test_add_kmip_client_certificate_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/certificates")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"name": "name", "id": "feddecaf-0000-0000-0000-1234567890ab", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "certificate": "certificate"}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type="application/json",
            status=201,
        )

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.kmip_client_certificate+json"
        collection_metadata_model["collectionTotal"] = 1

        # Construct a dict representation of a CreateKMIPClientCertificateObject model
        create_kmip_client_certificate_object_model = {}
        create_kmip_client_certificate_object_model["certificate"] = "testString"
        create_kmip_client_certificate_object_model["name"] = "testString"

        # Set up parameter values
        adapter_id = "testString"
        bluemix_instance = "testString"
        metadata = collection_metadata_model
        resources = [create_kmip_client_certificate_object_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "adapter_id": adapter_id,
            "bluemix_instance": bluemix_instance,
            "metadata": metadata,
            "resources": resources,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.add_kmip_client_certificate(**req_copy)

    def test_add_kmip_client_certificate_value_error_with_retries(self):
        # Enable retries and run test_add_kmip_client_certificate_value_error.
        _service.enable_retries()
        self.test_add_kmip_client_certificate_value_error()

        # Disable retries and run test_add_kmip_client_certificate_value_error.
        _service.disable_retries()
        self.test_add_kmip_client_certificate_value_error()


class TestGetKmipClientCertificate:
    """
    Test Class for get_kmip_client_certificate
    """

    @responses.activate
    def test_get_kmip_client_certificate_all_params(self):
        """
        get_kmip_client_certificate()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/certificates/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"name": "name", "id": "feddecaf-0000-0000-0000-1234567890ab", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "certificate": "certificate"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        adapter_id = "testString"
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"

        # Invoke method
        response = _service.get_kmip_client_certificate(
            adapter_id,
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_kmip_client_certificate_all_params_with_retries(self):
        # Enable retries and run test_get_kmip_client_certificate_all_params.
        _service.enable_retries()
        self.test_get_kmip_client_certificate_all_params()

        # Disable retries and run test_get_kmip_client_certificate_all_params.
        _service.disable_retries()
        self.test_get_kmip_client_certificate_all_params()

    @responses.activate
    def test_get_kmip_client_certificate_required_params(self):
        """
        test_get_kmip_client_certificate_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/certificates/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"name": "name", "id": "feddecaf-0000-0000-0000-1234567890ab", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "certificate": "certificate"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        adapter_id = "testString"
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.get_kmip_client_certificate(
            adapter_id,
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_kmip_client_certificate_required_params_with_retries(self):
        # Enable retries and run test_get_kmip_client_certificate_required_params.
        _service.enable_retries()
        self.test_get_kmip_client_certificate_required_params()

        # Disable retries and run test_get_kmip_client_certificate_required_params.
        _service.disable_retries()
        self.test_get_kmip_client_certificate_required_params()

    @responses.activate
    def test_get_kmip_client_certificate_value_error(self):
        """
        test_get_kmip_client_certificate_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/certificates/testString")
        mock_response = '{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"name": "name", "id": "feddecaf-0000-0000-0000-1234567890ab", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "certificate": "certificate"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type="application/json",
            status=200,
        )

        # Set up parameter values
        adapter_id = "testString"
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "adapter_id": adapter_id,
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_kmip_client_certificate(**req_copy)

    def test_get_kmip_client_certificate_value_error_with_retries(self):
        # Enable retries and run test_get_kmip_client_certificate_value_error.
        _service.enable_retries()
        self.test_get_kmip_client_certificate_value_error()

        # Disable retries and run test_get_kmip_client_certificate_value_error.
        _service.disable_retries()
        self.test_get_kmip_client_certificate_value_error()


class TestDeleteKmipClientCertificate:
    """
    Test Class for delete_kmip_client_certificate
    """

    @responses.activate
    def test_delete_kmip_client_certificate_all_params(self):
        """
        delete_kmip_client_certificate()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/certificates/testString")
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        adapter_id = "testString"
        id = "testString"
        bluemix_instance = "testString"
        correlation_id = "testString"

        # Invoke method
        response = _service.delete_kmip_client_certificate(
            adapter_id,
            id,
            bluemix_instance,
            correlation_id=correlation_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_kmip_client_certificate_all_params_with_retries(self):
        # Enable retries and run test_delete_kmip_client_certificate_all_params.
        _service.enable_retries()
        self.test_delete_kmip_client_certificate_all_params()

        # Disable retries and run test_delete_kmip_client_certificate_all_params.
        _service.disable_retries()
        self.test_delete_kmip_client_certificate_all_params()

    @responses.activate
    def test_delete_kmip_client_certificate_required_params(self):
        """
        test_delete_kmip_client_certificate_required_params()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/certificates/testString")
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        adapter_id = "testString"
        id = "testString"
        bluemix_instance = "testString"

        # Invoke method
        response = _service.delete_kmip_client_certificate(
            adapter_id,
            id,
            bluemix_instance,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_kmip_client_certificate_required_params_with_retries(self):
        # Enable retries and run test_delete_kmip_client_certificate_required_params.
        _service.enable_retries()
        self.test_delete_kmip_client_certificate_required_params()

        # Disable retries and run test_delete_kmip_client_certificate_required_params.
        _service.disable_retries()
        self.test_delete_kmip_client_certificate_required_params()

    @responses.activate
    def test_delete_kmip_client_certificate_value_error(self):
        """
        test_delete_kmip_client_certificate_value_error()
        """
        # Set up mock
        url = preprocess_url("/api/v2/kmip_adapters/testString/certificates/testString")
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        adapter_id = "testString"
        id = "testString"
        bluemix_instance = "testString"

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "adapter_id": adapter_id,
            "id": id,
            "bluemix_instance": bluemix_instance,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_kmip_client_certificate(**req_copy)

    def test_delete_kmip_client_certificate_value_error_with_retries(self):
        # Enable retries and run test_delete_kmip_client_certificate_value_error.
        _service.enable_retries()
        self.test_delete_kmip_client_certificate_value_error()

        # Disable retries and run test_delete_kmip_client_certificate_value_error.
        _service.disable_retries()
        self.test_delete_kmip_client_certificate_value_error()


# endregion
##############################################################################
# End of Service: KMIPAdapters
##############################################################################


##############################################################################
# Start of Model Tests
##############################################################################
# region


class TestModel_AllowedIPPort:
    """
    Test Class for AllowedIPPort
    """

    def test_allowed_ip_port_serialization(self):
        """
        Test serialization/deserialization for AllowedIPPort
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        allowed_ip_port_resource_model = {}  # AllowedIPPortResource

        # Construct a json representation of a AllowedIPPort model
        allowed_ip_port_model_json = {}
        allowed_ip_port_model_json["metadata"] = collection_metadata_model
        allowed_ip_port_model_json["resources"] = [allowed_ip_port_resource_model]

        # Construct a model instance of AllowedIPPort by calling from_dict on the json representation
        allowed_ip_port_model = AllowedIPPort.from_dict(allowed_ip_port_model_json)
        assert allowed_ip_port_model != False

        # Construct a model instance of AllowedIPPort by calling from_dict on the json representation
        allowed_ip_port_model_dict = AllowedIPPort.from_dict(allowed_ip_port_model_json).__dict__
        allowed_ip_port_model2 = AllowedIPPort(**allowed_ip_port_model_dict)

        # Verify the model instances are equivalent
        assert allowed_ip_port_model == allowed_ip_port_model2

        # Convert model instance back to dict and verify no loss of data
        allowed_ip_port_model_json2 = allowed_ip_port_model.to_dict()
        assert allowed_ip_port_model_json2 == allowed_ip_port_model_json


class TestModel_AllowedIPPortResource:
    """
    Test Class for AllowedIPPortResource
    """

    def test_allowed_ip_port_resource_serialization(self):
        """
        Test serialization/deserialization for AllowedIPPortResource
        """

        # Construct a json representation of a AllowedIPPortResource model
        allowed_ip_port_resource_model_json = {}

        # Construct a model instance of AllowedIPPortResource by calling from_dict on the json representation
        allowed_ip_port_resource_model = AllowedIPPortResource.from_dict(allowed_ip_port_resource_model_json)
        assert allowed_ip_port_resource_model != False

        # Construct a model instance of AllowedIPPortResource by calling from_dict on the json representation
        allowed_ip_port_resource_model_dict = AllowedIPPortResource.from_dict(
            allowed_ip_port_resource_model_json
        ).__dict__
        allowed_ip_port_resource_model2 = AllowedIPPortResource(**allowed_ip_port_resource_model_dict)

        # Verify the model instances are equivalent
        assert allowed_ip_port_resource_model == allowed_ip_port_resource_model2

        # Convert model instance back to dict and verify no loss of data
        allowed_ip_port_resource_model_json2 = allowed_ip_port_resource_model.to_dict()
        assert allowed_ip_port_resource_model_json2 == allowed_ip_port_resource_model_json


class TestModel_CollectionMetadata:
    """
    Test Class for CollectionMetadata
    """

    def test_collection_metadata_serialization(self):
        """
        Test serialization/deserialization for CollectionMetadata
        """

        # Construct a json representation of a CollectionMetadata model
        collection_metadata_model_json = {}
        collection_metadata_model_json["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model_json["collectionTotal"] = 1

        # Construct a model instance of CollectionMetadata by calling from_dict on the json representation
        collection_metadata_model = CollectionMetadata.from_dict(collection_metadata_model_json)
        assert collection_metadata_model != False

        # Construct a model instance of CollectionMetadata by calling from_dict on the json representation
        collection_metadata_model_dict = CollectionMetadata.from_dict(collection_metadata_model_json).__dict__
        collection_metadata_model2 = CollectionMetadata(**collection_metadata_model_dict)

        # Verify the model instances are equivalent
        assert collection_metadata_model == collection_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        collection_metadata_model_json2 = collection_metadata_model.to_dict()
        assert collection_metadata_model_json2 == collection_metadata_model_json


class TestModel_CollectionMetadataListKeys:
    """
    Test Class for CollectionMetadataListKeys
    """

    def test_collection_metadata_list_keys_serialization(self):
        """
        Test serialization/deserialization for CollectionMetadataListKeys
        """

        # Construct dict forms of any model objects needed in order to build this model.

        list_keys_metadata_properties_search_query_model = {}  # ListKeysMetadataPropertiesSearchQuery
        list_keys_metadata_properties_search_query_model["query"] = "testString"
        list_keys_metadata_properties_search_query_model["scopes"] = ["name"]
        list_keys_metadata_properties_search_query_model["not"] = True
        list_keys_metadata_properties_search_query_model["exact"] = True

        # Construct a json representation of a CollectionMetadataListKeys model
        collection_metadata_list_keys_model_json = {}
        collection_metadata_list_keys_model_json["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_list_keys_model_json["collectionTotal"] = 1
        collection_metadata_list_keys_model_json["incompleteSearch"] = True
        collection_metadata_list_keys_model_json["searchQuery"] = list_keys_metadata_properties_search_query_model

        # Construct a model instance of CollectionMetadataListKeys by calling from_dict on the json representation
        collection_metadata_list_keys_model = CollectionMetadataListKeys.from_dict(
            collection_metadata_list_keys_model_json
        )
        assert collection_metadata_list_keys_model != False

        # Construct a model instance of CollectionMetadataListKeys by calling from_dict on the json representation
        collection_metadata_list_keys_model_dict = CollectionMetadataListKeys.from_dict(
            collection_metadata_list_keys_model_json
        ).__dict__
        collection_metadata_list_keys_model2 = CollectionMetadataListKeys(**collection_metadata_list_keys_model_dict)

        # Verify the model instances are equivalent
        assert collection_metadata_list_keys_model == collection_metadata_list_keys_model2

        # Convert model instance back to dict and verify no loss of data
        collection_metadata_list_keys_model_json2 = collection_metadata_list_keys_model.to_dict()
        assert collection_metadata_list_keys_model_json2 == collection_metadata_list_keys_model_json


class TestModel_CollectionMetadataWithTotalCount:
    """
    Test Class for CollectionMetadataWithTotalCount
    """

    def test_collection_metadata_with_total_count_serialization(self):
        """
        Test serialization/deserialization for CollectionMetadataWithTotalCount
        """

        # Construct a json representation of a CollectionMetadataWithTotalCount model
        collection_metadata_with_total_count_model_json = {}
        collection_metadata_with_total_count_model_json[
            "collectionType"
        ] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_with_total_count_model_json["collectionTotal"] = 1
        collection_metadata_with_total_count_model_json["totalCount"] = 1

        # Construct a model instance of CollectionMetadataWithTotalCount by calling from_dict on the json representation
        collection_metadata_with_total_count_model = CollectionMetadataWithTotalCount.from_dict(
            collection_metadata_with_total_count_model_json
        )
        assert collection_metadata_with_total_count_model != False

        # Construct a model instance of CollectionMetadataWithTotalCount by calling from_dict on the json representation
        collection_metadata_with_total_count_model_dict = CollectionMetadataWithTotalCount.from_dict(
            collection_metadata_with_total_count_model_json
        ).__dict__
        collection_metadata_with_total_count_model2 = CollectionMetadataWithTotalCount(
            **collection_metadata_with_total_count_model_dict
        )

        # Verify the model instances are equivalent
        assert collection_metadata_with_total_count_model == collection_metadata_with_total_count_model2

        # Convert model instance back to dict and verify no loss of data
        collection_metadata_with_total_count_model_json2 = collection_metadata_with_total_count_model.to_dict()
        assert collection_metadata_with_total_count_model_json2 == collection_metadata_with_total_count_model_json


class TestModel_CreateKMIPAdapterObject:
    """
    Test Class for CreateKMIPAdapterObject
    """

    def test_create_kmip_adapter_object_serialization(self):
        """
        Test serialization/deserialization for CreateKMIPAdapterObject
        """

        # Construct dict forms of any model objects needed in order to build this model.

        kmip_profile_data_body_model = {}  # KMIPProfileDataBodyKMIPProfileDataNative
        kmip_profile_data_body_model["crk_id"] = "feddecaf-0000-0000-0000-1234567890ab"

        # Construct a json representation of a CreateKMIPAdapterObject model
        create_kmip_adapter_object_model_json = {}
        create_kmip_adapter_object_model_json["name"] = "kmip-adapter-name"
        create_kmip_adapter_object_model_json["description"] = "kmip adapter description"
        create_kmip_adapter_object_model_json["profile"] = "native_1.0"
        create_kmip_adapter_object_model_json["profile_data"] = kmip_profile_data_body_model

        # Construct a model instance of CreateKMIPAdapterObject by calling from_dict on the json representation
        create_kmip_adapter_object_model = CreateKMIPAdapterObject.from_dict(create_kmip_adapter_object_model_json)
        assert create_kmip_adapter_object_model != False

        # Construct a model instance of CreateKMIPAdapterObject by calling from_dict on the json representation
        create_kmip_adapter_object_model_dict = CreateKMIPAdapterObject.from_dict(
            create_kmip_adapter_object_model_json
        ).__dict__
        create_kmip_adapter_object_model2 = CreateKMIPAdapterObject(**create_kmip_adapter_object_model_dict)

        # Verify the model instances are equivalent
        assert create_kmip_adapter_object_model == create_kmip_adapter_object_model2

        # Convert model instance back to dict and verify no loss of data
        create_kmip_adapter_object_model_json2 = create_kmip_adapter_object_model.to_dict()
        assert create_kmip_adapter_object_model_json2 == create_kmip_adapter_object_model_json


class TestModel_CreateKMIPClientCertificateObject:
    """
    Test Class for CreateKMIPClientCertificateObject
    """

    def test_create_kmip_client_certificate_object_serialization(self):
        """
        Test serialization/deserialization for CreateKMIPClientCertificateObject
        """

        # Construct a json representation of a CreateKMIPClientCertificateObject model
        create_kmip_client_certificate_object_model_json = {}
        create_kmip_client_certificate_object_model_json["certificate"] = "testString"
        create_kmip_client_certificate_object_model_json["name"] = "testString"

        # Construct a model instance of CreateKMIPClientCertificateObject by calling from_dict on the json representation
        create_kmip_client_certificate_object_model = CreateKMIPClientCertificateObject.from_dict(
            create_kmip_client_certificate_object_model_json
        )
        assert create_kmip_client_certificate_object_model != False

        # Construct a model instance of CreateKMIPClientCertificateObject by calling from_dict on the json representation
        create_kmip_client_certificate_object_model_dict = CreateKMIPClientCertificateObject.from_dict(
            create_kmip_client_certificate_object_model_json
        ).__dict__
        create_kmip_client_certificate_object_model2 = CreateKMIPClientCertificateObject(
            **create_kmip_client_certificate_object_model_dict
        )

        # Verify the model instances are equivalent
        assert create_kmip_client_certificate_object_model == create_kmip_client_certificate_object_model2

        # Convert model instance back to dict and verify no loss of data
        create_kmip_client_certificate_object_model_json2 = create_kmip_client_certificate_object_model.to_dict()
        assert create_kmip_client_certificate_object_model_json2 == create_kmip_client_certificate_object_model_json


class TestModel_DeleteKey:
    """
    Test Class for DeleteKey
    """

    def test_delete_key_serialization(self):
        """
        Test serialization/deserialization for DeleteKey
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        dual_auth_key_metadata_model = {}  # DualAuthKeyMetadata
        dual_auth_key_metadata_model["enabled"] = True
        dual_auth_key_metadata_model["keySetForDeletion"] = True

        rotation_key_metadata_model = {}  # RotationKeyMetadata
        rotation_key_metadata_model["enabled"] = True
        rotation_key_metadata_model["interval_month"] = 3

        key_with_payload_model = {}  # KeyWithPayload
        key_with_payload_model["type"] = "application/vnd.ibm.kms.key+json"
        key_with_payload_model["name"] = "testString"
        key_with_payload_model["aliases"] = ["testString"]
        key_with_payload_model["description"] = "testString"
        key_with_payload_model["tags"] = ["testString"]
        key_with_payload_model["extractable"] = True
        key_with_payload_model["keyRingID"] = "testString"
        key_with_payload_model["algorithmBitSize"] = 256
        key_with_payload_model["algorithmMode"] = "CBC_PAD"
        key_with_payload_model["dualAuthDelete"] = dual_auth_key_metadata_model
        key_with_payload_model["rotation"] = rotation_key_metadata_model
        key_with_payload_model["restoreExpirationDate"] = "2000-03-21T00:00:00Z"
        key_with_payload_model["restoreAllowed"] = True
        key_with_payload_model["purgeAllowed"] = True
        key_with_payload_model["purgeAllowedFrom"] = "2000-03-21T00:00:00Z"
        key_with_payload_model["purgeScheduledOn"] = "2000-03-21T00:00:00Z"

        # Construct a json representation of a DeleteKey model
        delete_key_model_json = {}
        delete_key_model_json["metadata"] = collection_metadata_model
        delete_key_model_json["resources"] = [key_with_payload_model]

        # Construct a model instance of DeleteKey by calling from_dict on the json representation
        delete_key_model = DeleteKey.from_dict(delete_key_model_json)
        assert delete_key_model != False

        # Construct a model instance of DeleteKey by calling from_dict on the json representation
        delete_key_model_dict = DeleteKey.from_dict(delete_key_model_json).__dict__
        delete_key_model2 = DeleteKey(**delete_key_model_dict)

        # Verify the model instances are equivalent
        assert delete_key_model == delete_key_model2

        # Convert model instance back to dict and verify no loss of data
        delete_key_model_json2 = delete_key_model.to_dict()
        assert delete_key_model_json2 == delete_key_model_json


class TestModel_DualAuthDeleteProperties:
    """
    Test Class for DualAuthDeleteProperties
    """

    def test_dual_auth_delete_properties_serialization(self):
        """
        Test serialization/deserialization for DualAuthDeleteProperties
        """

        # Construct a json representation of a DualAuthDeleteProperties model
        dual_auth_delete_properties_model_json = {}
        dual_auth_delete_properties_model_json["enabled"] = True

        # Construct a model instance of DualAuthDeleteProperties by calling from_dict on the json representation
        dual_auth_delete_properties_model = DualAuthDeleteProperties.from_dict(dual_auth_delete_properties_model_json)
        assert dual_auth_delete_properties_model != False

        # Construct a model instance of DualAuthDeleteProperties by calling from_dict on the json representation
        dual_auth_delete_properties_model_dict = DualAuthDeleteProperties.from_dict(
            dual_auth_delete_properties_model_json
        ).__dict__
        dual_auth_delete_properties_model2 = DualAuthDeleteProperties(**dual_auth_delete_properties_model_dict)

        # Verify the model instances are equivalent
        assert dual_auth_delete_properties_model == dual_auth_delete_properties_model2

        # Convert model instance back to dict and verify no loss of data
        dual_auth_delete_properties_model_json2 = dual_auth_delete_properties_model.to_dict()
        assert dual_auth_delete_properties_model_json2 == dual_auth_delete_properties_model_json


class TestModel_DualAuthKeyMetadata:
    """
    Test Class for DualAuthKeyMetadata
    """

    def test_dual_auth_key_metadata_serialization(self):
        """
        Test serialization/deserialization for DualAuthKeyMetadata
        """

        # Construct a json representation of a DualAuthKeyMetadata model
        dual_auth_key_metadata_model_json = {}
        dual_auth_key_metadata_model_json["enabled"] = True
        dual_auth_key_metadata_model_json["keySetForDeletion"] = True

        # Construct a model instance of DualAuthKeyMetadata by calling from_dict on the json representation
        dual_auth_key_metadata_model = DualAuthKeyMetadata.from_dict(dual_auth_key_metadata_model_json)
        assert dual_auth_key_metadata_model != False

        # Construct a model instance of DualAuthKeyMetadata by calling from_dict on the json representation
        dual_auth_key_metadata_model_dict = DualAuthKeyMetadata.from_dict(dual_auth_key_metadata_model_json).__dict__
        dual_auth_key_metadata_model2 = DualAuthKeyMetadata(**dual_auth_key_metadata_model_dict)

        # Verify the model instances are equivalent
        assert dual_auth_key_metadata_model == dual_auth_key_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        dual_auth_key_metadata_model_json2 = dual_auth_key_metadata_model.to_dict()
        assert dual_auth_key_metadata_model_json2 == dual_auth_key_metadata_model_json


class TestModel_GetImportToken:
    """
    Test Class for GetImportToken
    """

    def test_get_import_token_serialization(self):
        """
        Test serialization/deserialization for GetImportToken
        """

        # Construct a json representation of a GetImportToken model
        get_import_token_model_json = {}
        get_import_token_model_json["expiration"] = 600
        get_import_token_model_json["maxAllowedRetrievals"] = 1

        # Construct a model instance of GetImportToken by calling from_dict on the json representation
        get_import_token_model = GetImportToken.from_dict(get_import_token_model_json)
        assert get_import_token_model != False

        # Construct a model instance of GetImportToken by calling from_dict on the json representation
        get_import_token_model_dict = GetImportToken.from_dict(get_import_token_model_json).__dict__
        get_import_token_model2 = GetImportToken(**get_import_token_model_dict)

        # Verify the model instances are equivalent
        assert get_import_token_model == get_import_token_model2

        # Convert model instance back to dict and verify no loss of data
        get_import_token_model_json2 = get_import_token_model.to_dict()
        assert get_import_token_model_json2 == get_import_token_model_json


class TestModel_GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem:
    """
    Test Class for GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem
    """

    def test_get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model = (
            {}
        )  # GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model[
            "allowed_network"
        ] = "public-and-private"

        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model = (
            {}
        )  # GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model[
            "enabled"
        ] = True
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model[
            "attributes"
        ] = get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model

        # Construct a json representation of a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem model
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model_json = {}
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model_json[
            "policy_type"
        ] = "testString"
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model_json[
            "policy_data"
        ] = get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model = (
            GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem.from_dict(
                get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model_json
            )
        )
        assert get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model != False

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model_dict = (
            GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem.from_dict(
                get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model_json
            ).__dict__
        )
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model2 = (
            GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem(
                **get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model
            == get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model_json2 = (
            get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model.to_dict()
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model_json2
            == get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model_json
        )


class TestModel_GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData:
    """
    Test Class for GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData
    """

    def test_get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData
        """

        # Construct dict forms of any model objects needed in order to build this model.

        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model = (
            {}
        )  # GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model[
            "allowed_network"
        ] = "public-and-private"

        # Construct a json representation of a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData model
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model_json = {}
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model_json[
            "enabled"
        ] = True
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model_json[
            "attributes"
        ] = get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model = (
            GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData.from_dict(
                get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model_json
            )
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model != False
        )

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model_dict = (
            GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData.from_dict(
                get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model_json
            ).__dict__
        )
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model2 = (
            GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData(
                **get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model
            == get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model_json2 = (
            get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model.to_dict()
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model_json2
            == get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model_json
        )


class TestModel_GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes:
    """
    Test Class for GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes
    """

    def test_get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes
        """

        # Construct a json representation of a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes model
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model_json = (
            {}
        )
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model_json[
            "allowed_network"
        ] = "public-and-private"

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model = GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes.from_dict(
            get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model_json
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model
            != False
        )

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model_dict = GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes.from_dict(
            get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model_json
        ).__dict__
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model2 = GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes(
            **get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model
            == get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model_json2 = (
            get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model.to_dict()
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model_json2
            == get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model_json
        )


class TestModel_GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem:
    """
    Test Class for GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem
    """

    def test_get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model = (
            {}
        )  # GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model[
            "create_root_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model[
            "create_standard_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model[
            "import_root_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model[
            "import_standard_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model[
            "enforce_token"
        ] = True

        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model = (
            {}
        )  # GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model[
            "enabled"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model[
            "attributes"
        ] = get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model

        # Construct a json representation of a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem model
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model_json = {}
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model_json[
            "policy_type"
        ] = "testString"
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model_json[
            "policy_data"
        ] = get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model = (
            GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem.from_dict(
                get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model_json
            )
        )
        assert get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model != False

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model_dict = (
            GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem.from_dict(
                get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model_json
            ).__dict__
        )
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model2 = (
            GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem(
                **get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model
            == get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model_json2 = (
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model.to_dict()
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model_json2
            == get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model_json
        )


class TestModel_GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData:
    """
    Test Class for GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData
    """

    def test_get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData
        """

        # Construct dict forms of any model objects needed in order to build this model.

        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model = (
            {}
        )  # GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model[
            "create_root_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model[
            "create_standard_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model[
            "import_root_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model[
            "import_standard_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model[
            "enforce_token"
        ] = True

        # Construct a json representation of a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData model
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model_json = (
            {}
        )
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model_json[
            "enabled"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model_json[
            "attributes"
        ] = get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model = GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData.from_dict(
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model_json
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model
            != False
        )

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model_dict = GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData.from_dict(
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model_json
        ).__dict__
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model2 = GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData(
            **get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model
            == get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model_json2 = (
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model.to_dict()
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model_json2
            == get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model_json
        )


class TestModel_GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes:
    """
    Test Class for GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes
    """

    def test_get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes
        """

        # Construct a json representation of a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes model
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model_json = (
            {}
        )
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model_json[
            "create_root_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model_json[
            "create_standard_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model_json[
            "import_root_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model_json[
            "import_standard_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model_json[
            "enforce_token"
        ] = True

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model = GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes.from_dict(
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model_json
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model
            != False
        )

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model_dict = GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes.from_dict(
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model_json
        ).__dict__
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model2 = GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes(
            **get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model
            == get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model_json2 = (
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model.to_dict()
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model_json2
            == get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model_json
        )


class TestModel_GetInstancePolicyAllowedIPResourcesItem:
    """
    Test Class for GetInstancePolicyAllowedIPResourcesItem
    """

    def test_get_instance_policy_allowed_ip_resources_item_serialization(self):
        """
        Test serialization/deserialization for GetInstancePolicyAllowedIPResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model = (
            {}
        )  # GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes
        get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]

        get_instance_policy_allowed_ip_resources_item_policy_data_model = (
            {}
        )  # GetInstancePolicyAllowedIPResourcesItemPolicyData
        get_instance_policy_allowed_ip_resources_item_policy_data_model["enabled"] = True
        get_instance_policy_allowed_ip_resources_item_policy_data_model[
            "attributes"
        ] = get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model

        # Construct a json representation of a GetInstancePolicyAllowedIPResourcesItem model
        get_instance_policy_allowed_ip_resources_item_model_json = {}
        get_instance_policy_allowed_ip_resources_item_model_json["policy_type"] = "testString"
        get_instance_policy_allowed_ip_resources_item_model_json[
            "policy_data"
        ] = get_instance_policy_allowed_ip_resources_item_policy_data_model

        # Construct a model instance of GetInstancePolicyAllowedIPResourcesItem by calling from_dict on the json representation
        get_instance_policy_allowed_ip_resources_item_model = GetInstancePolicyAllowedIPResourcesItem.from_dict(
            get_instance_policy_allowed_ip_resources_item_model_json
        )
        assert get_instance_policy_allowed_ip_resources_item_model != False

        # Construct a model instance of GetInstancePolicyAllowedIPResourcesItem by calling from_dict on the json representation
        get_instance_policy_allowed_ip_resources_item_model_dict = GetInstancePolicyAllowedIPResourcesItem.from_dict(
            get_instance_policy_allowed_ip_resources_item_model_json
        ).__dict__
        get_instance_policy_allowed_ip_resources_item_model2 = GetInstancePolicyAllowedIPResourcesItem(
            **get_instance_policy_allowed_ip_resources_item_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policy_allowed_ip_resources_item_model == get_instance_policy_allowed_ip_resources_item_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policy_allowed_ip_resources_item_model_json2 = (
            get_instance_policy_allowed_ip_resources_item_model.to_dict()
        )
        assert (
            get_instance_policy_allowed_ip_resources_item_model_json2
            == get_instance_policy_allowed_ip_resources_item_model_json
        )


class TestModel_GetInstancePolicyAllowedIPResourcesItemPolicyData:
    """
    Test Class for GetInstancePolicyAllowedIPResourcesItemPolicyData
    """

    def test_get_instance_policy_allowed_ip_resources_item_policy_data_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePolicyAllowedIPResourcesItemPolicyData
        """

        # Construct dict forms of any model objects needed in order to build this model.

        get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model = (
            {}
        )  # GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes
        get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]

        # Construct a json representation of a GetInstancePolicyAllowedIPResourcesItemPolicyData model
        get_instance_policy_allowed_ip_resources_item_policy_data_model_json = {}
        get_instance_policy_allowed_ip_resources_item_policy_data_model_json["enabled"] = True
        get_instance_policy_allowed_ip_resources_item_policy_data_model_json[
            "attributes"
        ] = get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model

        # Construct a model instance of GetInstancePolicyAllowedIPResourcesItemPolicyData by calling from_dict on the json representation
        get_instance_policy_allowed_ip_resources_item_policy_data_model = (
            GetInstancePolicyAllowedIPResourcesItemPolicyData.from_dict(
                get_instance_policy_allowed_ip_resources_item_policy_data_model_json
            )
        )
        assert get_instance_policy_allowed_ip_resources_item_policy_data_model != False

        # Construct a model instance of GetInstancePolicyAllowedIPResourcesItemPolicyData by calling from_dict on the json representation
        get_instance_policy_allowed_ip_resources_item_policy_data_model_dict = (
            GetInstancePolicyAllowedIPResourcesItemPolicyData.from_dict(
                get_instance_policy_allowed_ip_resources_item_policy_data_model_json
            ).__dict__
        )
        get_instance_policy_allowed_ip_resources_item_policy_data_model2 = (
            GetInstancePolicyAllowedIPResourcesItemPolicyData(
                **get_instance_policy_allowed_ip_resources_item_policy_data_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policy_allowed_ip_resources_item_policy_data_model
            == get_instance_policy_allowed_ip_resources_item_policy_data_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policy_allowed_ip_resources_item_policy_data_model_json2 = (
            get_instance_policy_allowed_ip_resources_item_policy_data_model.to_dict()
        )
        assert (
            get_instance_policy_allowed_ip_resources_item_policy_data_model_json2
            == get_instance_policy_allowed_ip_resources_item_policy_data_model_json
        )


class TestModel_GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes:
    """
    Test Class for GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes
    """

    def test_get_instance_policy_allowed_ip_resources_item_policy_data_attributes_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes
        """

        # Construct a json representation of a GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes model
        get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model_json = {}
        get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model_json["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]

        # Construct a model instance of GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes by calling from_dict on the json representation
        get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model = (
            GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes.from_dict(
                get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model_json
            )
        )
        assert get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model != False

        # Construct a model instance of GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes by calling from_dict on the json representation
        get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model_dict = (
            GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes.from_dict(
                get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model_json
            ).__dict__
        )
        get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model2 = (
            GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes(
                **get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model
            == get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model_json2 = (
            get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model.to_dict()
        )
        assert (
            get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model_json2
            == get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model_json
        )


class TestModel_GetInstancePolicyDualAuthDeleteResourcesItem:
    """
    Test Class for GetInstancePolicyDualAuthDeleteResourcesItem
    """

    def test_get_instance_policy_dual_auth_delete_resources_item_serialization(self):
        """
        Test serialization/deserialization for GetInstancePolicyDualAuthDeleteResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        dual_auth_delete_properties_model = {}  # DualAuthDeleteProperties
        dual_auth_delete_properties_model["enabled"] = True

        # Construct a json representation of a GetInstancePolicyDualAuthDeleteResourcesItem model
        get_instance_policy_dual_auth_delete_resources_item_model_json = {}
        get_instance_policy_dual_auth_delete_resources_item_model_json["policy_type"] = "testString"
        get_instance_policy_dual_auth_delete_resources_item_model_json[
            "policy_data"
        ] = dual_auth_delete_properties_model

        # Construct a model instance of GetInstancePolicyDualAuthDeleteResourcesItem by calling from_dict on the json representation
        get_instance_policy_dual_auth_delete_resources_item_model = (
            GetInstancePolicyDualAuthDeleteResourcesItem.from_dict(
                get_instance_policy_dual_auth_delete_resources_item_model_json
            )
        )
        assert get_instance_policy_dual_auth_delete_resources_item_model != False

        # Construct a model instance of GetInstancePolicyDualAuthDeleteResourcesItem by calling from_dict on the json representation
        get_instance_policy_dual_auth_delete_resources_item_model_dict = (
            GetInstancePolicyDualAuthDeleteResourcesItem.from_dict(
                get_instance_policy_dual_auth_delete_resources_item_model_json
            ).__dict__
        )
        get_instance_policy_dual_auth_delete_resources_item_model2 = GetInstancePolicyDualAuthDeleteResourcesItem(
            **get_instance_policy_dual_auth_delete_resources_item_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policy_dual_auth_delete_resources_item_model
            == get_instance_policy_dual_auth_delete_resources_item_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policy_dual_auth_delete_resources_item_model_json2 = (
            get_instance_policy_dual_auth_delete_resources_item_model.to_dict()
        )
        assert (
            get_instance_policy_dual_auth_delete_resources_item_model_json2
            == get_instance_policy_dual_auth_delete_resources_item_model_json
        )


class TestModel_GetInstancePolicyMetricsResourcesItem:
    """
    Test Class for GetInstancePolicyMetricsResourcesItem
    """

    def test_get_instance_policy_metrics_resources_item_serialization(self):
        """
        Test serialization/deserialization for GetInstancePolicyMetricsResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        metrics_properties_model = {}  # MetricsProperties
        metrics_properties_model["enabled"] = True

        # Construct a json representation of a GetInstancePolicyMetricsResourcesItem model
        get_instance_policy_metrics_resources_item_model_json = {}
        get_instance_policy_metrics_resources_item_model_json["policy_type"] = "testString"
        get_instance_policy_metrics_resources_item_model_json["policy_data"] = metrics_properties_model

        # Construct a model instance of GetInstancePolicyMetricsResourcesItem by calling from_dict on the json representation
        get_instance_policy_metrics_resources_item_model = GetInstancePolicyMetricsResourcesItem.from_dict(
            get_instance_policy_metrics_resources_item_model_json
        )
        assert get_instance_policy_metrics_resources_item_model != False

        # Construct a model instance of GetInstancePolicyMetricsResourcesItem by calling from_dict on the json representation
        get_instance_policy_metrics_resources_item_model_dict = GetInstancePolicyMetricsResourcesItem.from_dict(
            get_instance_policy_metrics_resources_item_model_json
        ).__dict__
        get_instance_policy_metrics_resources_item_model2 = GetInstancePolicyMetricsResourcesItem(
            **get_instance_policy_metrics_resources_item_model_dict
        )

        # Verify the model instances are equivalent
        assert get_instance_policy_metrics_resources_item_model == get_instance_policy_metrics_resources_item_model2

        # Convert model instance back to dict and verify no loss of data
        get_instance_policy_metrics_resources_item_model_json2 = (
            get_instance_policy_metrics_resources_item_model.to_dict()
        )
        assert (
            get_instance_policy_metrics_resources_item_model_json2
            == get_instance_policy_metrics_resources_item_model_json
        )


class TestModel_GetInstancePolicyRotationResourcesItem:
    """
    Test Class for GetInstancePolicyRotationResourcesItem
    """

    def test_get_instance_policy_rotation_resources_item_serialization(self):
        """
        Test serialization/deserialization for GetInstancePolicyRotationResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        get_instance_policy_rotation_resources_item_policy_data_attributes_model = (
            {}
        )  # GetInstancePolicyRotationResourcesItemPolicyDataAttributes
        get_instance_policy_rotation_resources_item_policy_data_attributes_model["interval_month"] = 3

        get_instance_policy_rotation_resources_item_policy_data_model = (
            {}
        )  # GetInstancePolicyRotationResourcesItemPolicyData
        get_instance_policy_rotation_resources_item_policy_data_model["enabled"] = True
        get_instance_policy_rotation_resources_item_policy_data_model[
            "attributes"
        ] = get_instance_policy_rotation_resources_item_policy_data_attributes_model

        # Construct a json representation of a GetInstancePolicyRotationResourcesItem model
        get_instance_policy_rotation_resources_item_model_json = {}
        get_instance_policy_rotation_resources_item_model_json["policy_type"] = "testString"
        get_instance_policy_rotation_resources_item_model_json[
            "policy_data"
        ] = get_instance_policy_rotation_resources_item_policy_data_model

        # Construct a model instance of GetInstancePolicyRotationResourcesItem by calling from_dict on the json representation
        get_instance_policy_rotation_resources_item_model = GetInstancePolicyRotationResourcesItem.from_dict(
            get_instance_policy_rotation_resources_item_model_json
        )
        assert get_instance_policy_rotation_resources_item_model != False

        # Construct a model instance of GetInstancePolicyRotationResourcesItem by calling from_dict on the json representation
        get_instance_policy_rotation_resources_item_model_dict = GetInstancePolicyRotationResourcesItem.from_dict(
            get_instance_policy_rotation_resources_item_model_json
        ).__dict__
        get_instance_policy_rotation_resources_item_model2 = GetInstancePolicyRotationResourcesItem(
            **get_instance_policy_rotation_resources_item_model_dict
        )

        # Verify the model instances are equivalent
        assert get_instance_policy_rotation_resources_item_model == get_instance_policy_rotation_resources_item_model2

        # Convert model instance back to dict and verify no loss of data
        get_instance_policy_rotation_resources_item_model_json2 = (
            get_instance_policy_rotation_resources_item_model.to_dict()
        )
        assert (
            get_instance_policy_rotation_resources_item_model_json2
            == get_instance_policy_rotation_resources_item_model_json
        )


class TestModel_GetInstancePolicyRotationResourcesItemPolicyData:
    """
    Test Class for GetInstancePolicyRotationResourcesItemPolicyData
    """

    def test_get_instance_policy_rotation_resources_item_policy_data_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePolicyRotationResourcesItemPolicyData
        """

        # Construct dict forms of any model objects needed in order to build this model.

        get_instance_policy_rotation_resources_item_policy_data_attributes_model = (
            {}
        )  # GetInstancePolicyRotationResourcesItemPolicyDataAttributes
        get_instance_policy_rotation_resources_item_policy_data_attributes_model["interval_month"] = 3

        # Construct a json representation of a GetInstancePolicyRotationResourcesItemPolicyData model
        get_instance_policy_rotation_resources_item_policy_data_model_json = {}
        get_instance_policy_rotation_resources_item_policy_data_model_json["enabled"] = True
        get_instance_policy_rotation_resources_item_policy_data_model_json[
            "attributes"
        ] = get_instance_policy_rotation_resources_item_policy_data_attributes_model

        # Construct a model instance of GetInstancePolicyRotationResourcesItemPolicyData by calling from_dict on the json representation
        get_instance_policy_rotation_resources_item_policy_data_model = (
            GetInstancePolicyRotationResourcesItemPolicyData.from_dict(
                get_instance_policy_rotation_resources_item_policy_data_model_json
            )
        )
        assert get_instance_policy_rotation_resources_item_policy_data_model != False

        # Construct a model instance of GetInstancePolicyRotationResourcesItemPolicyData by calling from_dict on the json representation
        get_instance_policy_rotation_resources_item_policy_data_model_dict = (
            GetInstancePolicyRotationResourcesItemPolicyData.from_dict(
                get_instance_policy_rotation_resources_item_policy_data_model_json
            ).__dict__
        )
        get_instance_policy_rotation_resources_item_policy_data_model2 = (
            GetInstancePolicyRotationResourcesItemPolicyData(
                **get_instance_policy_rotation_resources_item_policy_data_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policy_rotation_resources_item_policy_data_model
            == get_instance_policy_rotation_resources_item_policy_data_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policy_rotation_resources_item_policy_data_model_json2 = (
            get_instance_policy_rotation_resources_item_policy_data_model.to_dict()
        )
        assert (
            get_instance_policy_rotation_resources_item_policy_data_model_json2
            == get_instance_policy_rotation_resources_item_policy_data_model_json
        )


class TestModel_GetInstancePolicyRotationResourcesItemPolicyDataAttributes:
    """
    Test Class for GetInstancePolicyRotationResourcesItemPolicyDataAttributes
    """

    def test_get_instance_policy_rotation_resources_item_policy_data_attributes_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePolicyRotationResourcesItemPolicyDataAttributes
        """

        # Construct a json representation of a GetInstancePolicyRotationResourcesItemPolicyDataAttributes model
        get_instance_policy_rotation_resources_item_policy_data_attributes_model_json = {}
        get_instance_policy_rotation_resources_item_policy_data_attributes_model_json["interval_month"] = 3

        # Construct a model instance of GetInstancePolicyRotationResourcesItemPolicyDataAttributes by calling from_dict on the json representation
        get_instance_policy_rotation_resources_item_policy_data_attributes_model = (
            GetInstancePolicyRotationResourcesItemPolicyDataAttributes.from_dict(
                get_instance_policy_rotation_resources_item_policy_data_attributes_model_json
            )
        )
        assert get_instance_policy_rotation_resources_item_policy_data_attributes_model != False

        # Construct a model instance of GetInstancePolicyRotationResourcesItemPolicyDataAttributes by calling from_dict on the json representation
        get_instance_policy_rotation_resources_item_policy_data_attributes_model_dict = (
            GetInstancePolicyRotationResourcesItemPolicyDataAttributes.from_dict(
                get_instance_policy_rotation_resources_item_policy_data_attributes_model_json
            ).__dict__
        )
        get_instance_policy_rotation_resources_item_policy_data_attributes_model2 = (
            GetInstancePolicyRotationResourcesItemPolicyDataAttributes(
                **get_instance_policy_rotation_resources_item_policy_data_attributes_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policy_rotation_resources_item_policy_data_attributes_model
            == get_instance_policy_rotation_resources_item_policy_data_attributes_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policy_rotation_resources_item_policy_data_attributes_model_json2 = (
            get_instance_policy_rotation_resources_item_policy_data_attributes_model.to_dict()
        )
        assert (
            get_instance_policy_rotation_resources_item_policy_data_attributes_model_json2
            == get_instance_policy_rotation_resources_item_policy_data_attributes_model_json
        )


class TestModel_GetKey:
    """
    Test Class for GetKey
    """

    def test_get_key_serialization(self):
        """
        Test serialization/deserialization for GetKey
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        dual_auth_key_metadata_model = {}  # DualAuthKeyMetadata
        dual_auth_key_metadata_model["enabled"] = True
        dual_auth_key_metadata_model["keySetForDeletion"] = True

        rotation_key_metadata_model = {}  # RotationKeyMetadata
        rotation_key_metadata_model["enabled"] = True
        rotation_key_metadata_model["interval_month"] = 3

        key_with_payload_model = {}  # KeyWithPayload
        key_with_payload_model["type"] = "application/vnd.ibm.kms.key+json"
        key_with_payload_model["name"] = "testString"
        key_with_payload_model["aliases"] = ["testString"]
        key_with_payload_model["description"] = "testString"
        key_with_payload_model["tags"] = ["testString"]
        key_with_payload_model["extractable"] = True
        key_with_payload_model["keyRingID"] = "testString"
        key_with_payload_model["algorithmBitSize"] = 256
        key_with_payload_model["algorithmMode"] = "CBC_PAD"
        key_with_payload_model["dualAuthDelete"] = dual_auth_key_metadata_model
        key_with_payload_model["rotation"] = rotation_key_metadata_model
        key_with_payload_model["restoreExpirationDate"] = "2000-03-21T00:00:00Z"
        key_with_payload_model["restoreAllowed"] = True
        key_with_payload_model["purgeAllowed"] = True
        key_with_payload_model["purgeAllowedFrom"] = "2000-03-21T00:00:00Z"
        key_with_payload_model["purgeScheduledOn"] = "2000-03-21T00:00:00Z"

        # Construct a json representation of a GetKey model
        get_key_model_json = {}
        get_key_model_json["metadata"] = collection_metadata_model
        get_key_model_json["resources"] = [key_with_payload_model]

        # Construct a model instance of GetKey by calling from_dict on the json representation
        get_key_model = GetKey.from_dict(get_key_model_json)
        assert get_key_model != False

        # Construct a model instance of GetKey by calling from_dict on the json representation
        get_key_model_dict = GetKey.from_dict(get_key_model_json).__dict__
        get_key_model2 = GetKey(**get_key_model_dict)

        # Verify the model instances are equivalent
        assert get_key_model == get_key_model2

        # Convert model instance back to dict and verify no loss of data
        get_key_model_json2 = get_key_model.to_dict()
        assert get_key_model_json2 == get_key_model_json


class TestModel_GetKeyMetadata:
    """
    Test Class for GetKeyMetadata
    """

    def test_get_key_metadata_serialization(self):
        """
        Test serialization/deserialization for GetKeyMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        dual_auth_key_metadata_model = {}  # DualAuthKeyMetadata
        dual_auth_key_metadata_model["enabled"] = True
        dual_auth_key_metadata_model["keySetForDeletion"] = True

        rotation_key_metadata_model = {}  # RotationKeyMetadata
        rotation_key_metadata_model["enabled"] = True
        rotation_key_metadata_model["interval_month"] = 3

        key_full_representation_model = {}  # KeyFullRepresentation
        key_full_representation_model["type"] = "application/vnd.ibm.kms.key+json"
        key_full_representation_model["name"] = "testString"
        key_full_representation_model["aliases"] = ["testString"]
        key_full_representation_model["description"] = "testString"
        key_full_representation_model["tags"] = ["testString"]
        key_full_representation_model["extractable"] = True
        key_full_representation_model["keyRingID"] = "testString"
        key_full_representation_model["algorithmBitSize"] = 256
        key_full_representation_model["algorithmMode"] = "CBC_PAD"
        key_full_representation_model["dualAuthDelete"] = dual_auth_key_metadata_model
        key_full_representation_model["rotation"] = rotation_key_metadata_model
        key_full_representation_model["restoreExpirationDate"] = "2000-03-21T00:00:00Z"
        key_full_representation_model["restoreAllowed"] = True
        key_full_representation_model["purgeAllowed"] = True
        key_full_representation_model["purgeAllowedFrom"] = "2000-03-21T00:00:00Z"
        key_full_representation_model["purgeScheduledOn"] = "2000-03-21T00:00:00Z"

        # Construct a json representation of a GetKeyMetadata model
        get_key_metadata_model_json = {}
        get_key_metadata_model_json["metadata"] = collection_metadata_model
        get_key_metadata_model_json["resources"] = [key_full_representation_model]

        # Construct a model instance of GetKeyMetadata by calling from_dict on the json representation
        get_key_metadata_model = GetKeyMetadata.from_dict(get_key_metadata_model_json)
        assert get_key_metadata_model != False

        # Construct a model instance of GetKeyMetadata by calling from_dict on the json representation
        get_key_metadata_model_dict = GetKeyMetadata.from_dict(get_key_metadata_model_json).__dict__
        get_key_metadata_model2 = GetKeyMetadata(**get_key_metadata_model_dict)

        # Verify the model instances are equivalent
        assert get_key_metadata_model == get_key_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        get_key_metadata_model_json2 = get_key_metadata_model.to_dict()
        assert get_key_metadata_model_json2 == get_key_metadata_model_json


class TestModel_GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem:
    """
    Test Class for GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem
    """

    def test_get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        key_policy_dual_auth_delete_dual_auth_delete_model = {}  # KeyPolicyDualAuthDeleteDualAuthDelete
        key_policy_dual_auth_delete_dual_auth_delete_model["enabled"] = True

        # Construct a json representation of a GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem model
        get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model_json = {}
        get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model_json[
            "type"
        ] = "application/vnd.ibm.kms.policy+json"
        get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model_json[
            "dualAuthDelete"
        ] = key_policy_dual_auth_delete_dual_auth_delete_model

        # Construct a model instance of GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem by calling from_dict on the json representation
        get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model = (
            GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem.from_dict(
                get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model_json
            )
        )
        assert get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model != False

        # Construct a model instance of GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem by calling from_dict on the json representation
        get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model_dict = (
            GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem.from_dict(
                get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model_json
            ).__dict__
        )
        get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model2 = (
            GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem(
                **get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model
            == get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model_json2 = (
            get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model.to_dict()
        )
        assert (
            get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model_json2
            == get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model_json
        )


class TestModel_GetKeyPolicyRotationResourcesItem:
    """
    Test Class for GetKeyPolicyRotationResourcesItem
    """

    def test_get_key_policy_rotation_resources_item_serialization(self):
        """
        Test serialization/deserialization for GetKeyPolicyRotationResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        key_policy_rotation_rotation_model = {}  # KeyPolicyRotationRotation
        key_policy_rotation_rotation_model["enabled"] = True
        key_policy_rotation_rotation_model["interval_month"] = 1

        # Construct a json representation of a GetKeyPolicyRotationResourcesItem model
        get_key_policy_rotation_resources_item_model_json = {}
        get_key_policy_rotation_resources_item_model_json["type"] = "application/vnd.ibm.kms.policy+json"
        get_key_policy_rotation_resources_item_model_json["rotation"] = key_policy_rotation_rotation_model

        # Construct a model instance of GetKeyPolicyRotationResourcesItem by calling from_dict on the json representation
        get_key_policy_rotation_resources_item_model = GetKeyPolicyRotationResourcesItem.from_dict(
            get_key_policy_rotation_resources_item_model_json
        )
        assert get_key_policy_rotation_resources_item_model != False

        # Construct a model instance of GetKeyPolicyRotationResourcesItem by calling from_dict on the json representation
        get_key_policy_rotation_resources_item_model_dict = GetKeyPolicyRotationResourcesItem.from_dict(
            get_key_policy_rotation_resources_item_model_json
        ).__dict__
        get_key_policy_rotation_resources_item_model2 = GetKeyPolicyRotationResourcesItem(
            **get_key_policy_rotation_resources_item_model_dict
        )

        # Verify the model instances are equivalent
        assert get_key_policy_rotation_resources_item_model == get_key_policy_rotation_resources_item_model2

        # Convert model instance back to dict and verify no loss of data
        get_key_policy_rotation_resources_item_model_json2 = get_key_policy_rotation_resources_item_model.to_dict()
        assert get_key_policy_rotation_resources_item_model_json2 == get_key_policy_rotation_resources_item_model_json


class TestModel_GetMultipleKeyPoliciesResource:
    """
    Test Class for GetMultipleKeyPoliciesResource
    """

    def test_get_multiple_key_policies_resource_serialization(self):
        """
        Test serialization/deserialization for GetMultipleKeyPoliciesResource
        """

        # Construct dict forms of any model objects needed in order to build this model.

        get_multiple_key_policies_resource_dual_auth_delete_model = {}  # GetMultipleKeyPoliciesResourceDualAuthDelete
        get_multiple_key_policies_resource_dual_auth_delete_model["enabled"] = True

        key_policy_rotation_non_required_rotation_model = {}  # KeyPolicyRotationNonRequiredRotation
        key_policy_rotation_non_required_rotation_model["enabled"] = True
        key_policy_rotation_non_required_rotation_model["interval_month"] = 1

        # Construct a json representation of a GetMultipleKeyPoliciesResource model
        get_multiple_key_policies_resource_model_json = {}
        get_multiple_key_policies_resource_model_json[
            "dualAuthDelete"
        ] = get_multiple_key_policies_resource_dual_auth_delete_model
        get_multiple_key_policies_resource_model_json["rotation"] = key_policy_rotation_non_required_rotation_model

        # Construct a model instance of GetMultipleKeyPoliciesResource by calling from_dict on the json representation
        get_multiple_key_policies_resource_model = GetMultipleKeyPoliciesResource.from_dict(
            get_multiple_key_policies_resource_model_json
        )
        assert get_multiple_key_policies_resource_model != False

        # Construct a model instance of GetMultipleKeyPoliciesResource by calling from_dict on the json representation
        get_multiple_key_policies_resource_model_dict = GetMultipleKeyPoliciesResource.from_dict(
            get_multiple_key_policies_resource_model_json
        ).__dict__
        get_multiple_key_policies_resource_model2 = GetMultipleKeyPoliciesResource(
            **get_multiple_key_policies_resource_model_dict
        )

        # Verify the model instances are equivalent
        assert get_multiple_key_policies_resource_model == get_multiple_key_policies_resource_model2

        # Convert model instance back to dict and verify no loss of data
        get_multiple_key_policies_resource_model_json2 = get_multiple_key_policies_resource_model.to_dict()
        assert get_multiple_key_policies_resource_model_json2 == get_multiple_key_policies_resource_model_json


class TestModel_GetMultipleKeyPoliciesResourceDualAuthDelete:
    """
    Test Class for GetMultipleKeyPoliciesResourceDualAuthDelete
    """

    def test_get_multiple_key_policies_resource_dual_auth_delete_serialization(self):
        """
        Test serialization/deserialization for GetMultipleKeyPoliciesResourceDualAuthDelete
        """

        # Construct a json representation of a GetMultipleKeyPoliciesResourceDualAuthDelete model
        get_multiple_key_policies_resource_dual_auth_delete_model_json = {}
        get_multiple_key_policies_resource_dual_auth_delete_model_json["enabled"] = True

        # Construct a model instance of GetMultipleKeyPoliciesResourceDualAuthDelete by calling from_dict on the json representation
        get_multiple_key_policies_resource_dual_auth_delete_model = (
            GetMultipleKeyPoliciesResourceDualAuthDelete.from_dict(
                get_multiple_key_policies_resource_dual_auth_delete_model_json
            )
        )
        assert get_multiple_key_policies_resource_dual_auth_delete_model != False

        # Construct a model instance of GetMultipleKeyPoliciesResourceDualAuthDelete by calling from_dict on the json representation
        get_multiple_key_policies_resource_dual_auth_delete_model_dict = (
            GetMultipleKeyPoliciesResourceDualAuthDelete.from_dict(
                get_multiple_key_policies_resource_dual_auth_delete_model_json
            ).__dict__
        )
        get_multiple_key_policies_resource_dual_auth_delete_model2 = GetMultipleKeyPoliciesResourceDualAuthDelete(
            **get_multiple_key_policies_resource_dual_auth_delete_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            get_multiple_key_policies_resource_dual_auth_delete_model
            == get_multiple_key_policies_resource_dual_auth_delete_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_multiple_key_policies_resource_dual_auth_delete_model_json2 = (
            get_multiple_key_policies_resource_dual_auth_delete_model.to_dict()
        )
        assert (
            get_multiple_key_policies_resource_dual_auth_delete_model_json2
            == get_multiple_key_policies_resource_dual_auth_delete_model_json
        )


class TestModel_ImportToken:
    """
    Test Class for ImportToken
    """

    def test_import_token_serialization(self):
        """
        Test serialization/deserialization for ImportToken
        """

        # Construct a json representation of a ImportToken model
        import_token_model_json = {}
        import_token_model_json["expiration"] = 600
        import_token_model_json["maxAllowedRetrievals"] = 1

        # Construct a model instance of ImportToken by calling from_dict on the json representation
        import_token_model = ImportToken.from_dict(import_token_model_json)
        assert import_token_model != False

        # Construct a model instance of ImportToken by calling from_dict on the json representation
        import_token_model_dict = ImportToken.from_dict(import_token_model_json).__dict__
        import_token_model2 = ImportToken(**import_token_model_dict)

        # Verify the model instances are equivalent
        assert import_token_model == import_token_model2

        # Convert model instance back to dict and verify no loss of data
        import_token_model_json2 = import_token_model.to_dict()
        assert import_token_model_json2 == import_token_model_json


class TestModel_InstancePolicyAllowedIPPolicyData:
    """
    Test Class for InstancePolicyAllowedIPPolicyData
    """

    def test_instance_policy_allowed_ip_policy_data_serialization(self):
        """
        Test serialization/deserialization for InstancePolicyAllowedIPPolicyData
        """

        # Construct dict forms of any model objects needed in order to build this model.

        instance_policy_allowed_ip_policy_data_attributes_model = {}  # InstancePolicyAllowedIPPolicyDataAttributes
        instance_policy_allowed_ip_policy_data_attributes_model["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]

        # Construct a json representation of a InstancePolicyAllowedIPPolicyData model
        instance_policy_allowed_ip_policy_data_model_json = {}
        instance_policy_allowed_ip_policy_data_model_json["enabled"] = True
        instance_policy_allowed_ip_policy_data_model_json[
            "attributes"
        ] = instance_policy_allowed_ip_policy_data_attributes_model

        # Construct a model instance of InstancePolicyAllowedIPPolicyData by calling from_dict on the json representation
        instance_policy_allowed_ip_policy_data_model = InstancePolicyAllowedIPPolicyData.from_dict(
            instance_policy_allowed_ip_policy_data_model_json
        )
        assert instance_policy_allowed_ip_policy_data_model != False

        # Construct a model instance of InstancePolicyAllowedIPPolicyData by calling from_dict on the json representation
        instance_policy_allowed_ip_policy_data_model_dict = InstancePolicyAllowedIPPolicyData.from_dict(
            instance_policy_allowed_ip_policy_data_model_json
        ).__dict__
        instance_policy_allowed_ip_policy_data_model2 = InstancePolicyAllowedIPPolicyData(
            **instance_policy_allowed_ip_policy_data_model_dict
        )

        # Verify the model instances are equivalent
        assert instance_policy_allowed_ip_policy_data_model == instance_policy_allowed_ip_policy_data_model2

        # Convert model instance back to dict and verify no loss of data
        instance_policy_allowed_ip_policy_data_model_json2 = instance_policy_allowed_ip_policy_data_model.to_dict()
        assert instance_policy_allowed_ip_policy_data_model_json2 == instance_policy_allowed_ip_policy_data_model_json


class TestModel_InstancePolicyAllowedIPPolicyDataAttributes:
    """
    Test Class for InstancePolicyAllowedIPPolicyDataAttributes
    """

    def test_instance_policy_allowed_ip_policy_data_attributes_serialization(self):
        """
        Test serialization/deserialization for InstancePolicyAllowedIPPolicyDataAttributes
        """

        # Construct a json representation of a InstancePolicyAllowedIPPolicyDataAttributes model
        instance_policy_allowed_ip_policy_data_attributes_model_json = {}
        instance_policy_allowed_ip_policy_data_attributes_model_json["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]

        # Construct a model instance of InstancePolicyAllowedIPPolicyDataAttributes by calling from_dict on the json representation
        instance_policy_allowed_ip_policy_data_attributes_model = InstancePolicyAllowedIPPolicyDataAttributes.from_dict(
            instance_policy_allowed_ip_policy_data_attributes_model_json
        )
        assert instance_policy_allowed_ip_policy_data_attributes_model != False

        # Construct a model instance of InstancePolicyAllowedIPPolicyDataAttributes by calling from_dict on the json representation
        instance_policy_allowed_ip_policy_data_attributes_model_dict = (
            InstancePolicyAllowedIPPolicyDataAttributes.from_dict(
                instance_policy_allowed_ip_policy_data_attributes_model_json
            ).__dict__
        )
        instance_policy_allowed_ip_policy_data_attributes_model2 = InstancePolicyAllowedIPPolicyDataAttributes(
            **instance_policy_allowed_ip_policy_data_attributes_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            instance_policy_allowed_ip_policy_data_attributes_model
            == instance_policy_allowed_ip_policy_data_attributes_model2
        )

        # Convert model instance back to dict and verify no loss of data
        instance_policy_allowed_ip_policy_data_attributes_model_json2 = (
            instance_policy_allowed_ip_policy_data_attributes_model.to_dict()
        )
        assert (
            instance_policy_allowed_ip_policy_data_attributes_model_json2
            == instance_policy_allowed_ip_policy_data_attributes_model_json
        )


class TestModel_InstancePolicyAllowedNetworkPolicyData:
    """
    Test Class for InstancePolicyAllowedNetworkPolicyData
    """

    def test_instance_policy_allowed_network_policy_data_serialization(self):
        """
        Test serialization/deserialization for InstancePolicyAllowedNetworkPolicyData
        """

        # Construct dict forms of any model objects needed in order to build this model.

        instance_policy_allowed_network_policy_data_attributes_model = (
            {}
        )  # InstancePolicyAllowedNetworkPolicyDataAttributes
        instance_policy_allowed_network_policy_data_attributes_model["allowed_network"] = "public-and-private"

        # Construct a json representation of a InstancePolicyAllowedNetworkPolicyData model
        instance_policy_allowed_network_policy_data_model_json = {}
        instance_policy_allowed_network_policy_data_model_json["enabled"] = True
        instance_policy_allowed_network_policy_data_model_json[
            "attributes"
        ] = instance_policy_allowed_network_policy_data_attributes_model

        # Construct a model instance of InstancePolicyAllowedNetworkPolicyData by calling from_dict on the json representation
        instance_policy_allowed_network_policy_data_model = InstancePolicyAllowedNetworkPolicyData.from_dict(
            instance_policy_allowed_network_policy_data_model_json
        )
        assert instance_policy_allowed_network_policy_data_model != False

        # Construct a model instance of InstancePolicyAllowedNetworkPolicyData by calling from_dict on the json representation
        instance_policy_allowed_network_policy_data_model_dict = InstancePolicyAllowedNetworkPolicyData.from_dict(
            instance_policy_allowed_network_policy_data_model_json
        ).__dict__
        instance_policy_allowed_network_policy_data_model2 = InstancePolicyAllowedNetworkPolicyData(
            **instance_policy_allowed_network_policy_data_model_dict
        )

        # Verify the model instances are equivalent
        assert instance_policy_allowed_network_policy_data_model == instance_policy_allowed_network_policy_data_model2

        # Convert model instance back to dict and verify no loss of data
        instance_policy_allowed_network_policy_data_model_json2 = (
            instance_policy_allowed_network_policy_data_model.to_dict()
        )
        assert (
            instance_policy_allowed_network_policy_data_model_json2
            == instance_policy_allowed_network_policy_data_model_json
        )


class TestModel_InstancePolicyAllowedNetworkPolicyDataAttributes:
    """
    Test Class for InstancePolicyAllowedNetworkPolicyDataAttributes
    """

    def test_instance_policy_allowed_network_policy_data_attributes_serialization(self):
        """
        Test serialization/deserialization for InstancePolicyAllowedNetworkPolicyDataAttributes
        """

        # Construct a json representation of a InstancePolicyAllowedNetworkPolicyDataAttributes model
        instance_policy_allowed_network_policy_data_attributes_model_json = {}
        instance_policy_allowed_network_policy_data_attributes_model_json["allowed_network"] = "public-and-private"

        # Construct a model instance of InstancePolicyAllowedNetworkPolicyDataAttributes by calling from_dict on the json representation
        instance_policy_allowed_network_policy_data_attributes_model = (
            InstancePolicyAllowedNetworkPolicyDataAttributes.from_dict(
                instance_policy_allowed_network_policy_data_attributes_model_json
            )
        )
        assert instance_policy_allowed_network_policy_data_attributes_model != False

        # Construct a model instance of InstancePolicyAllowedNetworkPolicyDataAttributes by calling from_dict on the json representation
        instance_policy_allowed_network_policy_data_attributes_model_dict = (
            InstancePolicyAllowedNetworkPolicyDataAttributes.from_dict(
                instance_policy_allowed_network_policy_data_attributes_model_json
            ).__dict__
        )
        instance_policy_allowed_network_policy_data_attributes_model2 = (
            InstancePolicyAllowedNetworkPolicyDataAttributes(
                **instance_policy_allowed_network_policy_data_attributes_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            instance_policy_allowed_network_policy_data_attributes_model
            == instance_policy_allowed_network_policy_data_attributes_model2
        )

        # Convert model instance back to dict and verify no loss of data
        instance_policy_allowed_network_policy_data_attributes_model_json2 = (
            instance_policy_allowed_network_policy_data_attributes_model.to_dict()
        )
        assert (
            instance_policy_allowed_network_policy_data_attributes_model_json2
            == instance_policy_allowed_network_policy_data_attributes_model_json
        )


class TestModel_InstancePolicyKeyCreateImportAccessPolicyData:
    """
    Test Class for InstancePolicyKeyCreateImportAccessPolicyData
    """

    def test_instance_policy_key_create_import_access_policy_data_serialization(self):
        """
        Test serialization/deserialization for InstancePolicyKeyCreateImportAccessPolicyData
        """

        # Construct dict forms of any model objects needed in order to build this model.

        instance_policy_key_create_import_access_policy_data_attributes_model = (
            {}
        )  # InstancePolicyKeyCreateImportAccessPolicyDataAttributes
        instance_policy_key_create_import_access_policy_data_attributes_model["create_root_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model["create_standard_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model["import_root_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model["import_standard_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model["enforce_token"] = True

        # Construct a json representation of a InstancePolicyKeyCreateImportAccessPolicyData model
        instance_policy_key_create_import_access_policy_data_model_json = {}
        instance_policy_key_create_import_access_policy_data_model_json["enabled"] = True
        instance_policy_key_create_import_access_policy_data_model_json[
            "attributes"
        ] = instance_policy_key_create_import_access_policy_data_attributes_model

        # Construct a model instance of InstancePolicyKeyCreateImportAccessPolicyData by calling from_dict on the json representation
        instance_policy_key_create_import_access_policy_data_model = (
            InstancePolicyKeyCreateImportAccessPolicyData.from_dict(
                instance_policy_key_create_import_access_policy_data_model_json
            )
        )
        assert instance_policy_key_create_import_access_policy_data_model != False

        # Construct a model instance of InstancePolicyKeyCreateImportAccessPolicyData by calling from_dict on the json representation
        instance_policy_key_create_import_access_policy_data_model_dict = (
            InstancePolicyKeyCreateImportAccessPolicyData.from_dict(
                instance_policy_key_create_import_access_policy_data_model_json
            ).__dict__
        )
        instance_policy_key_create_import_access_policy_data_model2 = InstancePolicyKeyCreateImportAccessPolicyData(
            **instance_policy_key_create_import_access_policy_data_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            instance_policy_key_create_import_access_policy_data_model
            == instance_policy_key_create_import_access_policy_data_model2
        )

        # Convert model instance back to dict and verify no loss of data
        instance_policy_key_create_import_access_policy_data_model_json2 = (
            instance_policy_key_create_import_access_policy_data_model.to_dict()
        )
        assert (
            instance_policy_key_create_import_access_policy_data_model_json2
            == instance_policy_key_create_import_access_policy_data_model_json
        )


class TestModel_InstancePolicyKeyCreateImportAccessPolicyDataAttributes:
    """
    Test Class for InstancePolicyKeyCreateImportAccessPolicyDataAttributes
    """

    def test_instance_policy_key_create_import_access_policy_data_attributes_serialization(
        self,
    ):
        """
        Test serialization/deserialization for InstancePolicyKeyCreateImportAccessPolicyDataAttributes
        """

        # Construct a json representation of a InstancePolicyKeyCreateImportAccessPolicyDataAttributes model
        instance_policy_key_create_import_access_policy_data_attributes_model_json = {}
        instance_policy_key_create_import_access_policy_data_attributes_model_json["create_root_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model_json["create_standard_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model_json["import_root_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model_json["import_standard_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model_json["enforce_token"] = True

        # Construct a model instance of InstancePolicyKeyCreateImportAccessPolicyDataAttributes by calling from_dict on the json representation
        instance_policy_key_create_import_access_policy_data_attributes_model = (
            InstancePolicyKeyCreateImportAccessPolicyDataAttributes.from_dict(
                instance_policy_key_create_import_access_policy_data_attributes_model_json
            )
        )
        assert instance_policy_key_create_import_access_policy_data_attributes_model != False

        # Construct a model instance of InstancePolicyKeyCreateImportAccessPolicyDataAttributes by calling from_dict on the json representation
        instance_policy_key_create_import_access_policy_data_attributes_model_dict = (
            InstancePolicyKeyCreateImportAccessPolicyDataAttributes.from_dict(
                instance_policy_key_create_import_access_policy_data_attributes_model_json
            ).__dict__
        )
        instance_policy_key_create_import_access_policy_data_attributes_model2 = (
            InstancePolicyKeyCreateImportAccessPolicyDataAttributes(
                **instance_policy_key_create_import_access_policy_data_attributes_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            instance_policy_key_create_import_access_policy_data_attributes_model
            == instance_policy_key_create_import_access_policy_data_attributes_model2
        )

        # Convert model instance back to dict and verify no loss of data
        instance_policy_key_create_import_access_policy_data_attributes_model_json2 = (
            instance_policy_key_create_import_access_policy_data_attributes_model.to_dict()
        )
        assert (
            instance_policy_key_create_import_access_policy_data_attributes_model_json2
            == instance_policy_key_create_import_access_policy_data_attributes_model_json
        )


class TestModel_InstancePolicyProperties:
    """
    Test Class for InstancePolicyProperties
    """

    def test_instance_policy_properties_serialization(self):
        """
        Test serialization/deserialization for InstancePolicyProperties
        """

        # Construct dict forms of any model objects needed in order to build this model.

        instance_policy_properties_attributes_model = {}  # InstancePolicyPropertiesAttributes
        instance_policy_properties_attributes_model["allowed_network"] = "public-and-private"
        instance_policy_properties_attributes_model["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]
        instance_policy_properties_attributes_model["create_root_key"] = True
        instance_policy_properties_attributes_model["create_standard_key"] = True
        instance_policy_properties_attributes_model["import_root_key"] = True
        instance_policy_properties_attributes_model["import_standard_key"] = True
        instance_policy_properties_attributes_model["enforce_token"] = True
        instance_policy_properties_attributes_model["interval_month"] = 3

        # Construct a json representation of a InstancePolicyProperties model
        instance_policy_properties_model_json = {}
        instance_policy_properties_model_json["enabled"] = True
        instance_policy_properties_model_json["attributes"] = instance_policy_properties_attributes_model

        # Construct a model instance of InstancePolicyProperties by calling from_dict on the json representation
        instance_policy_properties_model = InstancePolicyProperties.from_dict(instance_policy_properties_model_json)
        assert instance_policy_properties_model != False

        # Construct a model instance of InstancePolicyProperties by calling from_dict on the json representation
        instance_policy_properties_model_dict = InstancePolicyProperties.from_dict(
            instance_policy_properties_model_json
        ).__dict__
        instance_policy_properties_model2 = InstancePolicyProperties(**instance_policy_properties_model_dict)

        # Verify the model instances are equivalent
        assert instance_policy_properties_model == instance_policy_properties_model2

        # Convert model instance back to dict and verify no loss of data
        instance_policy_properties_model_json2 = instance_policy_properties_model.to_dict()
        assert instance_policy_properties_model_json2 == instance_policy_properties_model_json


class TestModel_InstancePolicyPropertiesAttributes:
    """
    Test Class for InstancePolicyPropertiesAttributes
    """

    def test_instance_policy_properties_attributes_serialization(self):
        """
        Test serialization/deserialization for InstancePolicyPropertiesAttributes
        """

        # Construct a json representation of a InstancePolicyPropertiesAttributes model
        instance_policy_properties_attributes_model_json = {}
        instance_policy_properties_attributes_model_json["allowed_network"] = "public-and-private"
        instance_policy_properties_attributes_model_json["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]
        instance_policy_properties_attributes_model_json["create_root_key"] = True
        instance_policy_properties_attributes_model_json["create_standard_key"] = True
        instance_policy_properties_attributes_model_json["import_root_key"] = True
        instance_policy_properties_attributes_model_json["import_standard_key"] = True
        instance_policy_properties_attributes_model_json["enforce_token"] = True
        instance_policy_properties_attributes_model_json["interval_month"] = 3

        # Construct a model instance of InstancePolicyPropertiesAttributes by calling from_dict on the json representation
        instance_policy_properties_attributes_model = InstancePolicyPropertiesAttributes.from_dict(
            instance_policy_properties_attributes_model_json
        )
        assert instance_policy_properties_attributes_model != False

        # Construct a model instance of InstancePolicyPropertiesAttributes by calling from_dict on the json representation
        instance_policy_properties_attributes_model_dict = InstancePolicyPropertiesAttributes.from_dict(
            instance_policy_properties_attributes_model_json
        ).__dict__
        instance_policy_properties_attributes_model2 = InstancePolicyPropertiesAttributes(
            **instance_policy_properties_attributes_model_dict
        )

        # Verify the model instances are equivalent
        assert instance_policy_properties_attributes_model == instance_policy_properties_attributes_model2

        # Convert model instance back to dict and verify no loss of data
        instance_policy_properties_attributes_model_json2 = instance_policy_properties_attributes_model.to_dict()
        assert instance_policy_properties_attributes_model_json2 == instance_policy_properties_attributes_model_json


class TestModel_InstancePolicyResource:
    """
    Test Class for InstancePolicyResource
    """

    def test_instance_policy_resource_serialization(self):
        """
        Test serialization/deserialization for InstancePolicyResource
        """

        # Construct dict forms of any model objects needed in order to build this model.

        instance_policy_properties_attributes_model = {}  # InstancePolicyPropertiesAttributes
        instance_policy_properties_attributes_model["allowed_network"] = "public-and-private"
        instance_policy_properties_attributes_model["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]
        instance_policy_properties_attributes_model["create_root_key"] = True
        instance_policy_properties_attributes_model["create_standard_key"] = True
        instance_policy_properties_attributes_model["import_root_key"] = True
        instance_policy_properties_attributes_model["import_standard_key"] = True
        instance_policy_properties_attributes_model["enforce_token"] = True
        instance_policy_properties_attributes_model["interval_month"] = 3

        instance_policy_properties_model = {}  # InstancePolicyProperties
        instance_policy_properties_model["enabled"] = True
        instance_policy_properties_model["attributes"] = instance_policy_properties_attributes_model

        # Construct a json representation of a InstancePolicyResource model
        instance_policy_resource_model_json = {}
        instance_policy_resource_model_json["policy_type"] = "testString"
        instance_policy_resource_model_json["policy_data"] = instance_policy_properties_model

        # Construct a model instance of InstancePolicyResource by calling from_dict on the json representation
        instance_policy_resource_model = InstancePolicyResource.from_dict(instance_policy_resource_model_json)
        assert instance_policy_resource_model != False

        # Construct a model instance of InstancePolicyResource by calling from_dict on the json representation
        instance_policy_resource_model_dict = InstancePolicyResource.from_dict(
            instance_policy_resource_model_json
        ).__dict__
        instance_policy_resource_model2 = InstancePolicyResource(**instance_policy_resource_model_dict)

        # Verify the model instances are equivalent
        assert instance_policy_resource_model == instance_policy_resource_model2

        # Convert model instance back to dict and verify no loss of data
        instance_policy_resource_model_json2 = instance_policy_resource_model.to_dict()
        assert instance_policy_resource_model_json2 == instance_policy_resource_model_json


class TestModel_InstancePolicyRotationPolicyData:
    """
    Test Class for InstancePolicyRotationPolicyData
    """

    def test_instance_policy_rotation_policy_data_serialization(self):
        """
        Test serialization/deserialization for InstancePolicyRotationPolicyData
        """

        # Construct dict forms of any model objects needed in order to build this model.

        instance_policy_rotation_policy_data_attributes_model = {}  # InstancePolicyRotationPolicyDataAttributes
        instance_policy_rotation_policy_data_attributes_model["interval_month"] = 3

        # Construct a json representation of a InstancePolicyRotationPolicyData model
        instance_policy_rotation_policy_data_model_json = {}
        instance_policy_rotation_policy_data_model_json["enabled"] = True
        instance_policy_rotation_policy_data_model_json[
            "attributes"
        ] = instance_policy_rotation_policy_data_attributes_model

        # Construct a model instance of InstancePolicyRotationPolicyData by calling from_dict on the json representation
        instance_policy_rotation_policy_data_model = InstancePolicyRotationPolicyData.from_dict(
            instance_policy_rotation_policy_data_model_json
        )
        assert instance_policy_rotation_policy_data_model != False

        # Construct a model instance of InstancePolicyRotationPolicyData by calling from_dict on the json representation
        instance_policy_rotation_policy_data_model_dict = InstancePolicyRotationPolicyData.from_dict(
            instance_policy_rotation_policy_data_model_json
        ).__dict__
        instance_policy_rotation_policy_data_model2 = InstancePolicyRotationPolicyData(
            **instance_policy_rotation_policy_data_model_dict
        )

        # Verify the model instances are equivalent
        assert instance_policy_rotation_policy_data_model == instance_policy_rotation_policy_data_model2

        # Convert model instance back to dict and verify no loss of data
        instance_policy_rotation_policy_data_model_json2 = instance_policy_rotation_policy_data_model.to_dict()
        assert instance_policy_rotation_policy_data_model_json2 == instance_policy_rotation_policy_data_model_json


class TestModel_InstancePolicyRotationPolicyDataAttributes:
    """
    Test Class for InstancePolicyRotationPolicyDataAttributes
    """

    def test_instance_policy_rotation_policy_data_attributes_serialization(self):
        """
        Test serialization/deserialization for InstancePolicyRotationPolicyDataAttributes
        """

        # Construct a json representation of a InstancePolicyRotationPolicyDataAttributes model
        instance_policy_rotation_policy_data_attributes_model_json = {}
        instance_policy_rotation_policy_data_attributes_model_json["interval_month"] = 3

        # Construct a model instance of InstancePolicyRotationPolicyDataAttributes by calling from_dict on the json representation
        instance_policy_rotation_policy_data_attributes_model = InstancePolicyRotationPolicyDataAttributes.from_dict(
            instance_policy_rotation_policy_data_attributes_model_json
        )
        assert instance_policy_rotation_policy_data_attributes_model != False

        # Construct a model instance of InstancePolicyRotationPolicyDataAttributes by calling from_dict on the json representation
        instance_policy_rotation_policy_data_attributes_model_dict = (
            InstancePolicyRotationPolicyDataAttributes.from_dict(
                instance_policy_rotation_policy_data_attributes_model_json
            ).__dict__
        )
        instance_policy_rotation_policy_data_attributes_model2 = InstancePolicyRotationPolicyDataAttributes(
            **instance_policy_rotation_policy_data_attributes_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            instance_policy_rotation_policy_data_attributes_model
            == instance_policy_rotation_policy_data_attributes_model2
        )

        # Convert model instance back to dict and verify no loss of data
        instance_policy_rotation_policy_data_attributes_model_json2 = (
            instance_policy_rotation_policy_data_attributes_model.to_dict()
        )
        assert (
            instance_policy_rotation_policy_data_attributes_model_json2
            == instance_policy_rotation_policy_data_attributes_model_json
        )


class TestModel_KMIPAdapter:
    """
    Test Class for KMIPAdapter
    """

    def test_kmip_adapter_serialization(self):
        """
        Test serialization/deserialization for KMIPAdapter
        """

        # Construct dict forms of any model objects needed in order to build this model.

        kmip_profile_data_body_model = {}  # KMIPProfileDataBodyKMIPProfileDataNative
        kmip_profile_data_body_model["crk_id"] = "feddecaf-0000-0000-0000-1234567890ab"

        # Construct a json representation of a KMIPAdapter model
        kmip_adapter_model_json = {}
        kmip_adapter_model_json["id"] = "feddecaf-0000-0000-0000-1234567890ab"
        kmip_adapter_model_json["name"] = "kmip-adapter-name"
        kmip_adapter_model_json["created_at"] = "2019-01-01T12:00:00Z"
        kmip_adapter_model_json["created_by"] = "testString"
        kmip_adapter_model_json["updated_at"] = "2019-01-01T12:00:00Z"
        kmip_adapter_model_json["updated_by"] = "testString"
        kmip_adapter_model_json["profile"] = "native_1.0"
        kmip_adapter_model_json["description"] = "kmip adapter description"
        kmip_adapter_model_json["profile_data"] = kmip_profile_data_body_model

        # Construct a model instance of KMIPAdapter by calling from_dict on the json representation
        kmip_adapter_model = KMIPAdapter.from_dict(kmip_adapter_model_json)
        assert kmip_adapter_model != False

        # Construct a model instance of KMIPAdapter by calling from_dict on the json representation
        kmip_adapter_model_dict = KMIPAdapter.from_dict(kmip_adapter_model_json).__dict__
        kmip_adapter_model2 = KMIPAdapter(**kmip_adapter_model_dict)

        # Verify the model instances are equivalent
        assert kmip_adapter_model == kmip_adapter_model2

        # Convert model instance back to dict and verify no loss of data
        kmip_adapter_model_json2 = kmip_adapter_model.to_dict()
        assert kmip_adapter_model_json2 == kmip_adapter_model_json


class TestModel_KMIPClientCertificate:
    """
    Test Class for KMIPClientCertificate
    """

    def test_kmip_client_certificate_serialization(self):
        """
        Test serialization/deserialization for KMIPClientCertificate
        """

        # Construct a json representation of a KMIPClientCertificate model
        kmip_client_certificate_model_json = {}
        kmip_client_certificate_model_json["name"] = "testString"
        kmip_client_certificate_model_json["id"] = "feddecaf-0000-0000-0000-1234567890ab"
        kmip_client_certificate_model_json["created_at"] = "2019-01-01T12:00:00Z"
        kmip_client_certificate_model_json["created_by"] = "testString"
        kmip_client_certificate_model_json["certificate"] = "testString"

        # Construct a model instance of KMIPClientCertificate by calling from_dict on the json representation
        kmip_client_certificate_model = KMIPClientCertificate.from_dict(kmip_client_certificate_model_json)
        assert kmip_client_certificate_model != False

        # Construct a model instance of KMIPClientCertificate by calling from_dict on the json representation
        kmip_client_certificate_model_dict = KMIPClientCertificate.from_dict(
            kmip_client_certificate_model_json
        ).__dict__
        kmip_client_certificate_model2 = KMIPClientCertificate(**kmip_client_certificate_model_dict)

        # Verify the model instances are equivalent
        assert kmip_client_certificate_model == kmip_client_certificate_model2

        # Convert model instance back to dict and verify no loss of data
        kmip_client_certificate_model_json2 = kmip_client_certificate_model.to_dict()
        assert kmip_client_certificate_model_json2 == kmip_client_certificate_model_json


class TestModel_KMIPClientPartialCertificate:
    """
    Test Class for KMIPClientPartialCertificate
    """

    def test_kmip_client_partial_certificate_serialization(self):
        """
        Test serialization/deserialization for KMIPClientPartialCertificate
        """

        # Construct a json representation of a KMIPClientPartialCertificate model
        kmip_client_partial_certificate_model_json = {}
        kmip_client_partial_certificate_model_json["name"] = "testString"
        kmip_client_partial_certificate_model_json["id"] = "feddecaf-0000-0000-0000-1234567890ab"
        kmip_client_partial_certificate_model_json["created_at"] = "2019-01-01T12:00:00Z"
        kmip_client_partial_certificate_model_json["created_by"] = "testString"

        # Construct a model instance of KMIPClientPartialCertificate by calling from_dict on the json representation
        kmip_client_partial_certificate_model = KMIPClientPartialCertificate.from_dict(
            kmip_client_partial_certificate_model_json
        )
        assert kmip_client_partial_certificate_model != False

        # Construct a model instance of KMIPClientPartialCertificate by calling from_dict on the json representation
        kmip_client_partial_certificate_model_dict = KMIPClientPartialCertificate.from_dict(
            kmip_client_partial_certificate_model_json
        ).__dict__
        kmip_client_partial_certificate_model2 = KMIPClientPartialCertificate(
            **kmip_client_partial_certificate_model_dict
        )

        # Verify the model instances are equivalent
        assert kmip_client_partial_certificate_model == kmip_client_partial_certificate_model2

        # Convert model instance back to dict and verify no loss of data
        kmip_client_partial_certificate_model_json2 = kmip_client_partial_certificate_model.to_dict()
        assert kmip_client_partial_certificate_model_json2 == kmip_client_partial_certificate_model_json


class TestModel_KMIPObject:
    """
    Test Class for KMIPObject
    """

    def test_kmip_object_serialization(self):
        """
        Test serialization/deserialization for KMIPObject
        """

        # Construct a json representation of a KMIPObject model
        kmip_object_model_json = {}
        kmip_object_model_json["id"] = "feddecaf-0000-0000-0000-1234567890ab"
        kmip_object_model_json["kmip_object_type"] = 2
        kmip_object_model_json["state"] = 1
        kmip_object_model_json["created_at"] = "2019-01-01T12:00:00Z"
        kmip_object_model_json["created_by_kmip_client_cert_id"] = "feddecaf-0000-0000-0000-1234567890ab"
        kmip_object_model_json["created_by"] = "testString"
        kmip_object_model_json["updated_at"] = "2019-01-01T12:00:00Z"
        kmip_object_model_json["updated_by_kmip_client_cert_id"] = "feddecaf-0000-0000-0000-1234567890ab"
        kmip_object_model_json["updated_by"] = "testString"
        kmip_object_model_json["destroyed_at"] = "2019-01-01T12:00:00Z"
        kmip_object_model_json["destroyed_by_kmip_client_cert_id"] = "feddecaf-0000-0000-0000-1234567890ab"
        kmip_object_model_json["destroyed_by"] = "testString"
        kmip_object_model_json["recoverable"] = True

        # Construct a model instance of KMIPObject by calling from_dict on the json representation
        kmip_object_model = KMIPObject.from_dict(kmip_object_model_json)
        assert kmip_object_model != False

        # Construct a model instance of KMIPObject by calling from_dict on the json representation
        kmip_object_model_dict = KMIPObject.from_dict(kmip_object_model_json).__dict__
        kmip_object_model2 = KMIPObject(**kmip_object_model_dict)

        # Verify the model instances are equivalent
        assert kmip_object_model == kmip_object_model2

        # Convert model instance back to dict and verify no loss of data
        kmip_object_model_json2 = kmip_object_model.to_dict()
        assert kmip_object_model_json2 == kmip_object_model_json


class TestModel_Key:
    """
    Test Class for Key
    """

    def test_key_serialization(self):
        """
        Test serialization/deserialization for Key
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_one_of_model = {}  # CollectionMetadataOneOfCollectionMetadata
        collection_metadata_one_of_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_one_of_model["collectionTotal"] = 1

        dual_auth_key_metadata_model = {}  # DualAuthKeyMetadata
        dual_auth_key_metadata_model["enabled"] = True
        dual_auth_key_metadata_model["keySetForDeletion"] = True

        rotation_key_metadata_model = {}  # RotationKeyMetadata
        rotation_key_metadata_model["enabled"] = True
        rotation_key_metadata_model["interval_month"] = 3

        key_with_payload_model = {}  # KeyWithPayload
        key_with_payload_model["type"] = "application/vnd.ibm.kms.key+json"
        key_with_payload_model["name"] = "testString"
        key_with_payload_model["aliases"] = ["testString"]
        key_with_payload_model["description"] = "testString"
        key_with_payload_model["tags"] = ["testString"]
        key_with_payload_model["extractable"] = True
        key_with_payload_model["keyRingID"] = "testString"
        key_with_payload_model["algorithmBitSize"] = 256
        key_with_payload_model["algorithmMode"] = "CBC_PAD"
        key_with_payload_model["dualAuthDelete"] = dual_auth_key_metadata_model
        key_with_payload_model["rotation"] = rotation_key_metadata_model
        key_with_payload_model["restoreExpirationDate"] = "2000-03-21T00:00:00Z"
        key_with_payload_model["restoreAllowed"] = True
        key_with_payload_model["purgeAllowed"] = True
        key_with_payload_model["purgeAllowedFrom"] = "2000-03-21T00:00:00Z"
        key_with_payload_model["purgeScheduledOn"] = "2000-03-21T00:00:00Z"

        # Construct a json representation of a Key model
        key_model_json = {}
        key_model_json["metadata"] = collection_metadata_one_of_model
        key_model_json["resources"] = [key_with_payload_model]

        # Construct a model instance of Key by calling from_dict on the json representation
        key_model = Key.from_dict(key_model_json)
        assert key_model != False

        # Construct a model instance of Key by calling from_dict on the json representation
        key_model_dict = Key.from_dict(key_model_json).__dict__
        key_model2 = Key(**key_model_dict)

        # Verify the model instances are equivalent
        assert key_model == key_model2

        # Convert model instance back to dict and verify no loss of data
        key_model_json2 = key_model.to_dict()
        assert key_model_json2 == key_model_json


class TestModel_KeyAlias:
    """
    Test Class for KeyAlias
    """

    def test_key_alias_serialization(self):
        """
        Test serialization/deserialization for KeyAlias
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        key_alias_resource_model = {}  # KeyAliasResource

        # Construct a json representation of a KeyAlias model
        key_alias_model_json = {}
        key_alias_model_json["metadata"] = collection_metadata_model
        key_alias_model_json["resources"] = [key_alias_resource_model]

        # Construct a model instance of KeyAlias by calling from_dict on the json representation
        key_alias_model = KeyAlias.from_dict(key_alias_model_json)
        assert key_alias_model != False

        # Construct a model instance of KeyAlias by calling from_dict on the json representation
        key_alias_model_dict = KeyAlias.from_dict(key_alias_model_json).__dict__
        key_alias_model2 = KeyAlias(**key_alias_model_dict)

        # Verify the model instances are equivalent
        assert key_alias_model == key_alias_model2

        # Convert model instance back to dict and verify no loss of data
        key_alias_model_json2 = key_alias_model.to_dict()
        assert key_alias_model_json2 == key_alias_model_json


class TestModel_KeyAliasResource:
    """
    Test Class for KeyAliasResource
    """

    def test_key_alias_resource_serialization(self):
        """
        Test serialization/deserialization for KeyAliasResource
        """

        # Construct a json representation of a KeyAliasResource model
        key_alias_resource_model_json = {}

        # Construct a model instance of KeyAliasResource by calling from_dict on the json representation
        key_alias_resource_model = KeyAliasResource.from_dict(key_alias_resource_model_json)
        assert key_alias_resource_model != False

        # Construct a model instance of KeyAliasResource by calling from_dict on the json representation
        key_alias_resource_model_dict = KeyAliasResource.from_dict(key_alias_resource_model_json).__dict__
        key_alias_resource_model2 = KeyAliasResource(**key_alias_resource_model_dict)

        # Verify the model instances are equivalent
        assert key_alias_resource_model == key_alias_resource_model2

        # Convert model instance back to dict and verify no loss of data
        key_alias_resource_model_json2 = key_alias_resource_model.to_dict()
        assert key_alias_resource_model_json2 == key_alias_resource_model_json


class TestModel_KeyFullRepresentation:
    """
    Test Class for KeyFullRepresentation
    """

    def test_key_full_representation_serialization(self):
        """
        Test serialization/deserialization for KeyFullRepresentation
        """

        # Construct dict forms of any model objects needed in order to build this model.

        dual_auth_key_metadata_model = {}  # DualAuthKeyMetadata
        dual_auth_key_metadata_model["enabled"] = True
        dual_auth_key_metadata_model["keySetForDeletion"] = True

        rotation_key_metadata_model = {}  # RotationKeyMetadata
        rotation_key_metadata_model["enabled"] = True
        rotation_key_metadata_model["interval_month"] = 3

        # Construct a json representation of a KeyFullRepresentation model
        key_full_representation_model_json = {}
        key_full_representation_model_json["type"] = "application/vnd.ibm.kms.key+json"
        key_full_representation_model_json["name"] = "testString"
        key_full_representation_model_json["aliases"] = ["testString"]
        key_full_representation_model_json["description"] = "testString"
        key_full_representation_model_json["tags"] = ["testString"]
        key_full_representation_model_json["extractable"] = True
        key_full_representation_model_json["keyRingID"] = "testString"
        key_full_representation_model_json["algorithmBitSize"] = 256
        key_full_representation_model_json["algorithmMode"] = "CBC_PAD"
        key_full_representation_model_json["dualAuthDelete"] = dual_auth_key_metadata_model
        key_full_representation_model_json["rotation"] = rotation_key_metadata_model
        key_full_representation_model_json["restoreExpirationDate"] = "2000-03-21T00:00:00Z"
        key_full_representation_model_json["restoreAllowed"] = True
        key_full_representation_model_json["purgeAllowed"] = True
        key_full_representation_model_json["purgeAllowedFrom"] = "2000-03-21T00:00:00Z"
        key_full_representation_model_json["purgeScheduledOn"] = "2000-03-21T00:00:00Z"

        # Construct a model instance of KeyFullRepresentation by calling from_dict on the json representation
        key_full_representation_model = KeyFullRepresentation.from_dict(key_full_representation_model_json)
        assert key_full_representation_model != False

        # Construct a model instance of KeyFullRepresentation by calling from_dict on the json representation
        key_full_representation_model_dict = KeyFullRepresentation.from_dict(
            key_full_representation_model_json
        ).__dict__
        key_full_representation_model2 = KeyFullRepresentation(**key_full_representation_model_dict)

        # Verify the model instances are equivalent
        assert key_full_representation_model == key_full_representation_model2

        # Convert model instance back to dict and verify no loss of data
        key_full_representation_model_json2 = key_full_representation_model.to_dict()
        assert key_full_representation_model_json2 == key_full_representation_model_json


class TestModel_KeyFullRepresentationAlgorithmMetadata:
    """
    Test Class for KeyFullRepresentationAlgorithmMetadata
    """

    def test_key_full_representation_algorithm_metadata_serialization(self):
        """
        Test serialization/deserialization for KeyFullRepresentationAlgorithmMetadata
        """

        # Construct a json representation of a KeyFullRepresentationAlgorithmMetadata model
        key_full_representation_algorithm_metadata_model_json = {}
        key_full_representation_algorithm_metadata_model_json["bitLength"] = "256"
        key_full_representation_algorithm_metadata_model_json["mode"] = "CBC_PAD"

        # Construct a model instance of KeyFullRepresentationAlgorithmMetadata by calling from_dict on the json representation
        key_full_representation_algorithm_metadata_model = KeyFullRepresentationAlgorithmMetadata.from_dict(
            key_full_representation_algorithm_metadata_model_json
        )
        assert key_full_representation_algorithm_metadata_model != False

        # Construct a model instance of KeyFullRepresentationAlgorithmMetadata by calling from_dict on the json representation
        key_full_representation_algorithm_metadata_model_dict = KeyFullRepresentationAlgorithmMetadata.from_dict(
            key_full_representation_algorithm_metadata_model_json
        ).__dict__
        key_full_representation_algorithm_metadata_model2 = KeyFullRepresentationAlgorithmMetadata(
            **key_full_representation_algorithm_metadata_model_dict
        )

        # Verify the model instances are equivalent
        assert key_full_representation_algorithm_metadata_model == key_full_representation_algorithm_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        key_full_representation_algorithm_metadata_model_json2 = (
            key_full_representation_algorithm_metadata_model.to_dict()
        )
        assert (
            key_full_representation_algorithm_metadata_model_json2
            == key_full_representation_algorithm_metadata_model_json
        )


class TestModel_KeyPolicyDualAuthDelete:
    """
    Test Class for KeyPolicyDualAuthDelete
    """

    def test_key_policy_dual_auth_delete_serialization(self):
        """
        Test serialization/deserialization for KeyPolicyDualAuthDelete
        """

        # Construct dict forms of any model objects needed in order to build this model.

        key_policy_dual_auth_delete_dual_auth_delete_model = {}  # KeyPolicyDualAuthDeleteDualAuthDelete
        key_policy_dual_auth_delete_dual_auth_delete_model["enabled"] = True

        # Construct a json representation of a KeyPolicyDualAuthDelete model
        key_policy_dual_auth_delete_model_json = {}
        key_policy_dual_auth_delete_model_json["type"] = "application/vnd.ibm.kms.policy+json"
        key_policy_dual_auth_delete_model_json["dualAuthDelete"] = key_policy_dual_auth_delete_dual_auth_delete_model

        # Construct a model instance of KeyPolicyDualAuthDelete by calling from_dict on the json representation
        key_policy_dual_auth_delete_model = KeyPolicyDualAuthDelete.from_dict(key_policy_dual_auth_delete_model_json)
        assert key_policy_dual_auth_delete_model != False

        # Construct a model instance of KeyPolicyDualAuthDelete by calling from_dict on the json representation
        key_policy_dual_auth_delete_model_dict = KeyPolicyDualAuthDelete.from_dict(
            key_policy_dual_auth_delete_model_json
        ).__dict__
        key_policy_dual_auth_delete_model2 = KeyPolicyDualAuthDelete(**key_policy_dual_auth_delete_model_dict)

        # Verify the model instances are equivalent
        assert key_policy_dual_auth_delete_model == key_policy_dual_auth_delete_model2

        # Convert model instance back to dict and verify no loss of data
        key_policy_dual_auth_delete_model_json2 = key_policy_dual_auth_delete_model.to_dict()
        assert key_policy_dual_auth_delete_model_json2 == key_policy_dual_auth_delete_model_json


class TestModel_KeyPolicyDualAuthDeleteDualAuthDelete:
    """
    Test Class for KeyPolicyDualAuthDeleteDualAuthDelete
    """

    def test_key_policy_dual_auth_delete_dual_auth_delete_serialization(self):
        """
        Test serialization/deserialization for KeyPolicyDualAuthDeleteDualAuthDelete
        """

        # Construct a json representation of a KeyPolicyDualAuthDeleteDualAuthDelete model
        key_policy_dual_auth_delete_dual_auth_delete_model_json = {}
        key_policy_dual_auth_delete_dual_auth_delete_model_json["enabled"] = True

        # Construct a model instance of KeyPolicyDualAuthDeleteDualAuthDelete by calling from_dict on the json representation
        key_policy_dual_auth_delete_dual_auth_delete_model = KeyPolicyDualAuthDeleteDualAuthDelete.from_dict(
            key_policy_dual_auth_delete_dual_auth_delete_model_json
        )
        assert key_policy_dual_auth_delete_dual_auth_delete_model != False

        # Construct a model instance of KeyPolicyDualAuthDeleteDualAuthDelete by calling from_dict on the json representation
        key_policy_dual_auth_delete_dual_auth_delete_model_dict = KeyPolicyDualAuthDeleteDualAuthDelete.from_dict(
            key_policy_dual_auth_delete_dual_auth_delete_model_json
        ).__dict__
        key_policy_dual_auth_delete_dual_auth_delete_model2 = KeyPolicyDualAuthDeleteDualAuthDelete(
            **key_policy_dual_auth_delete_dual_auth_delete_model_dict
        )

        # Verify the model instances are equivalent
        assert key_policy_dual_auth_delete_dual_auth_delete_model == key_policy_dual_auth_delete_dual_auth_delete_model2

        # Convert model instance back to dict and verify no loss of data
        key_policy_dual_auth_delete_dual_auth_delete_model_json2 = (
            key_policy_dual_auth_delete_dual_auth_delete_model.to_dict()
        )
        assert (
            key_policy_dual_auth_delete_dual_auth_delete_model_json2
            == key_policy_dual_auth_delete_dual_auth_delete_model_json
        )


class TestModel_KeyPolicyRotation:
    """
    Test Class for KeyPolicyRotation
    """

    def test_key_policy_rotation_serialization(self):
        """
        Test serialization/deserialization for KeyPolicyRotation
        """

        # Construct dict forms of any model objects needed in order to build this model.

        key_policy_rotation_rotation_model = {}  # KeyPolicyRotationRotation
        key_policy_rotation_rotation_model["enabled"] = True
        key_policy_rotation_rotation_model["interval_month"] = 1

        # Construct a json representation of a KeyPolicyRotation model
        key_policy_rotation_model_json = {}
        key_policy_rotation_model_json["type"] = "application/vnd.ibm.kms.policy+json"
        key_policy_rotation_model_json["rotation"] = key_policy_rotation_rotation_model

        # Construct a model instance of KeyPolicyRotation by calling from_dict on the json representation
        key_policy_rotation_model = KeyPolicyRotation.from_dict(key_policy_rotation_model_json)
        assert key_policy_rotation_model != False

        # Construct a model instance of KeyPolicyRotation by calling from_dict on the json representation
        key_policy_rotation_model_dict = KeyPolicyRotation.from_dict(key_policy_rotation_model_json).__dict__
        key_policy_rotation_model2 = KeyPolicyRotation(**key_policy_rotation_model_dict)

        # Verify the model instances are equivalent
        assert key_policy_rotation_model == key_policy_rotation_model2

        # Convert model instance back to dict and verify no loss of data
        key_policy_rotation_model_json2 = key_policy_rotation_model.to_dict()
        assert key_policy_rotation_model_json2 == key_policy_rotation_model_json


class TestModel_KeyPolicyRotationNonRequiredRotation:
    """
    Test Class for KeyPolicyRotationNonRequiredRotation
    """

    def test_key_policy_rotation_non_required_rotation_serialization(self):
        """
        Test serialization/deserialization for KeyPolicyRotationNonRequiredRotation
        """

        # Construct a json representation of a KeyPolicyRotationNonRequiredRotation model
        key_policy_rotation_non_required_rotation_model_json = {}
        key_policy_rotation_non_required_rotation_model_json["enabled"] = True
        key_policy_rotation_non_required_rotation_model_json["interval_month"] = 1

        # Construct a model instance of KeyPolicyRotationNonRequiredRotation by calling from_dict on the json representation
        key_policy_rotation_non_required_rotation_model = KeyPolicyRotationNonRequiredRotation.from_dict(
            key_policy_rotation_non_required_rotation_model_json
        )
        assert key_policy_rotation_non_required_rotation_model != False

        # Construct a model instance of KeyPolicyRotationNonRequiredRotation by calling from_dict on the json representation
        key_policy_rotation_non_required_rotation_model_dict = KeyPolicyRotationNonRequiredRotation.from_dict(
            key_policy_rotation_non_required_rotation_model_json
        ).__dict__
        key_policy_rotation_non_required_rotation_model2 = KeyPolicyRotationNonRequiredRotation(
            **key_policy_rotation_non_required_rotation_model_dict
        )

        # Verify the model instances are equivalent
        assert key_policy_rotation_non_required_rotation_model == key_policy_rotation_non_required_rotation_model2

        # Convert model instance back to dict and verify no loss of data
        key_policy_rotation_non_required_rotation_model_json2 = (
            key_policy_rotation_non_required_rotation_model.to_dict()
        )
        assert (
            key_policy_rotation_non_required_rotation_model_json2
            == key_policy_rotation_non_required_rotation_model_json
        )


class TestModel_KeyPolicyRotationRotation:
    """
    Test Class for KeyPolicyRotationRotation
    """

    def test_key_policy_rotation_rotation_serialization(self):
        """
        Test serialization/deserialization for KeyPolicyRotationRotation
        """

        # Construct a json representation of a KeyPolicyRotationRotation model
        key_policy_rotation_rotation_model_json = {}
        key_policy_rotation_rotation_model_json["enabled"] = True
        key_policy_rotation_rotation_model_json["interval_month"] = 1

        # Construct a model instance of KeyPolicyRotationRotation by calling from_dict on the json representation
        key_policy_rotation_rotation_model = KeyPolicyRotationRotation.from_dict(
            key_policy_rotation_rotation_model_json
        )
        assert key_policy_rotation_rotation_model != False

        # Construct a model instance of KeyPolicyRotationRotation by calling from_dict on the json representation
        key_policy_rotation_rotation_model_dict = KeyPolicyRotationRotation.from_dict(
            key_policy_rotation_rotation_model_json
        ).__dict__
        key_policy_rotation_rotation_model2 = KeyPolicyRotationRotation(**key_policy_rotation_rotation_model_dict)

        # Verify the model instances are equivalent
        assert key_policy_rotation_rotation_model == key_policy_rotation_rotation_model2

        # Convert model instance back to dict and verify no loss of data
        key_policy_rotation_rotation_model_json2 = key_policy_rotation_rotation_model.to_dict()
        assert key_policy_rotation_rotation_model_json2 == key_policy_rotation_rotation_model_json


class TestModel_KeyRing:
    """
    Test Class for KeyRing
    """

    def test_key_ring_serialization(self):
        """
        Test serialization/deserialization for KeyRing
        """

        # Construct a json representation of a KeyRing model
        key_ring_model_json = {}
        key_ring_model_json["id"] = "testString"
        key_ring_model_json["creationDate"] = "2000-03-21T00:00:00Z"
        key_ring_model_json["createdBy"] = "testString"

        # Construct a model instance of KeyRing by calling from_dict on the json representation
        key_ring_model = KeyRing.from_dict(key_ring_model_json)
        assert key_ring_model != False

        # Construct a model instance of KeyRing by calling from_dict on the json representation
        key_ring_model_dict = KeyRing.from_dict(key_ring_model_json).__dict__
        key_ring_model2 = KeyRing(**key_ring_model_dict)

        # Verify the model instances are equivalent
        assert key_ring_model == key_ring_model2

        # Convert model instance back to dict and verify no loss of data
        key_ring_model_json2 = key_ring_model.to_dict()
        assert key_ring_model_json2 == key_ring_model_json


class TestModel_KeyVersion:
    """
    Test Class for KeyVersion
    """

    def test_key_version_serialization(self):
        """
        Test serialization/deserialization for KeyVersion
        """

        # Construct a json representation of a KeyVersion model
        key_version_model_json = {}

        # Construct a model instance of KeyVersion by calling from_dict on the json representation
        key_version_model = KeyVersion.from_dict(key_version_model_json)
        assert key_version_model != False

        # Construct a model instance of KeyVersion by calling from_dict on the json representation
        key_version_model_dict = KeyVersion.from_dict(key_version_model_json).__dict__
        key_version_model2 = KeyVersion(**key_version_model_dict)

        # Verify the model instances are equivalent
        assert key_version_model == key_version_model2

        # Convert model instance back to dict and verify no loss of data
        key_version_model_json2 = key_version_model.to_dict()
        assert key_version_model_json2 == key_version_model_json


class TestModel_KeyWithPayload:
    """
    Test Class for KeyWithPayload
    """

    def test_key_with_payload_serialization(self):
        """
        Test serialization/deserialization for KeyWithPayload
        """

        # Construct dict forms of any model objects needed in order to build this model.

        dual_auth_key_metadata_model = {}  # DualAuthKeyMetadata
        dual_auth_key_metadata_model["enabled"] = True
        dual_auth_key_metadata_model["keySetForDeletion"] = True

        rotation_key_metadata_model = {}  # RotationKeyMetadata
        rotation_key_metadata_model["enabled"] = True
        rotation_key_metadata_model["interval_month"] = 3

        # Construct a json representation of a KeyWithPayload model
        key_with_payload_model_json = {}
        key_with_payload_model_json["type"] = "application/vnd.ibm.kms.key+json"
        key_with_payload_model_json["name"] = "testString"
        key_with_payload_model_json["aliases"] = ["testString"]
        key_with_payload_model_json["description"] = "testString"
        key_with_payload_model_json["tags"] = ["testString"]
        key_with_payload_model_json["extractable"] = True
        key_with_payload_model_json["keyRingID"] = "testString"
        key_with_payload_model_json["algorithmBitSize"] = 256
        key_with_payload_model_json["algorithmMode"] = "CBC_PAD"
        key_with_payload_model_json["dualAuthDelete"] = dual_auth_key_metadata_model
        key_with_payload_model_json["rotation"] = rotation_key_metadata_model
        key_with_payload_model_json["restoreExpirationDate"] = "2000-03-21T00:00:00Z"
        key_with_payload_model_json["restoreAllowed"] = True
        key_with_payload_model_json["purgeAllowed"] = True
        key_with_payload_model_json["purgeAllowedFrom"] = "2000-03-21T00:00:00Z"
        key_with_payload_model_json["purgeScheduledOn"] = "2000-03-21T00:00:00Z"

        # Construct a model instance of KeyWithPayload by calling from_dict on the json representation
        key_with_payload_model = KeyWithPayload.from_dict(key_with_payload_model_json)
        assert key_with_payload_model != False

        # Construct a model instance of KeyWithPayload by calling from_dict on the json representation
        key_with_payload_model_dict = KeyWithPayload.from_dict(key_with_payload_model_json).__dict__
        key_with_payload_model2 = KeyWithPayload(**key_with_payload_model_dict)

        # Verify the model instances are equivalent
        assert key_with_payload_model == key_with_payload_model2

        # Convert model instance back to dict and verify no loss of data
        key_with_payload_model_json2 = key_with_payload_model.to_dict()
        assert key_with_payload_model_json2 == key_with_payload_model_json


class TestModel_KeyWithPayloadAlgorithmMetadata:
    """
    Test Class for KeyWithPayloadAlgorithmMetadata
    """

    def test_key_with_payload_algorithm_metadata_serialization(self):
        """
        Test serialization/deserialization for KeyWithPayloadAlgorithmMetadata
        """

        # Construct a json representation of a KeyWithPayloadAlgorithmMetadata model
        key_with_payload_algorithm_metadata_model_json = {}
        key_with_payload_algorithm_metadata_model_json["bitLength"] = "256"
        key_with_payload_algorithm_metadata_model_json["mode"] = "CBC_PAD"

        # Construct a model instance of KeyWithPayloadAlgorithmMetadata by calling from_dict on the json representation
        key_with_payload_algorithm_metadata_model = KeyWithPayloadAlgorithmMetadata.from_dict(
            key_with_payload_algorithm_metadata_model_json
        )
        assert key_with_payload_algorithm_metadata_model != False

        # Construct a model instance of KeyWithPayloadAlgorithmMetadata by calling from_dict on the json representation
        key_with_payload_algorithm_metadata_model_dict = KeyWithPayloadAlgorithmMetadata.from_dict(
            key_with_payload_algorithm_metadata_model_json
        ).__dict__
        key_with_payload_algorithm_metadata_model2 = KeyWithPayloadAlgorithmMetadata(
            **key_with_payload_algorithm_metadata_model_dict
        )

        # Verify the model instances are equivalent
        assert key_with_payload_algorithm_metadata_model == key_with_payload_algorithm_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        key_with_payload_algorithm_metadata_model_json2 = key_with_payload_algorithm_metadata_model.to_dict()
        assert key_with_payload_algorithm_metadata_model_json2 == key_with_payload_algorithm_metadata_model_json


class TestModel_ListKMIPAdapters:
    """
    Test Class for ListKMIPAdapters
    """

    def test_list_kmip_adapters_serialization(self):
        """
        Test serialization/deserialization for ListKMIPAdapters
        """

        # Construct dict forms of any model objects needed in order to build this model.

        list_collection_metadata_model = {}  # ListCollectionMetadataCollectionMetadataWithTotalCount
        list_collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        list_collection_metadata_model["collectionTotal"] = 1
        list_collection_metadata_model["totalCount"] = 1

        kmip_profile_data_body_model = {}  # KMIPProfileDataBodyKMIPProfileDataNative
        kmip_profile_data_body_model["crk_id"] = "feddecaf-0000-0000-0000-1234567890ab"

        kmip_adapter_model = {}  # KMIPAdapter
        kmip_adapter_model["id"] = "feddecaf-0000-0000-0000-1234567890ab"
        kmip_adapter_model["name"] = "kmip-adapter-name"
        kmip_adapter_model["created_at"] = "2019-01-01T12:00:00Z"
        kmip_adapter_model["created_by"] = "testString"
        kmip_adapter_model["updated_at"] = "2019-01-01T12:00:00Z"
        kmip_adapter_model["updated_by"] = "testString"
        kmip_adapter_model["profile"] = "native_1.0"
        kmip_adapter_model["description"] = "kmip adapter description"
        kmip_adapter_model["profile_data"] = kmip_profile_data_body_model

        # Construct a json representation of a ListKMIPAdapters model
        list_kmip_adapters_model_json = {}
        list_kmip_adapters_model_json["metadata"] = list_collection_metadata_model
        list_kmip_adapters_model_json["resources"] = [kmip_adapter_model]

        # Construct a model instance of ListKMIPAdapters by calling from_dict on the json representation
        list_kmip_adapters_model = ListKMIPAdapters.from_dict(list_kmip_adapters_model_json)
        assert list_kmip_adapters_model != False

        # Construct a model instance of ListKMIPAdapters by calling from_dict on the json representation
        list_kmip_adapters_model_dict = ListKMIPAdapters.from_dict(list_kmip_adapters_model_json).__dict__
        list_kmip_adapters_model2 = ListKMIPAdapters(**list_kmip_adapters_model_dict)

        # Verify the model instances are equivalent
        assert list_kmip_adapters_model == list_kmip_adapters_model2

        # Convert model instance back to dict and verify no loss of data
        list_kmip_adapters_model_json2 = list_kmip_adapters_model.to_dict()
        assert list_kmip_adapters_model_json2 == list_kmip_adapters_model_json


class TestModel_ListKMIPAdaptersWithTotalCount:
    """
    Test Class for ListKMIPAdaptersWithTotalCount
    """

    def test_list_kmip_adapters_with_total_count_serialization(self):
        """
        Test serialization/deserialization for ListKMIPAdaptersWithTotalCount
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_with_total_count_model = {}  # CollectionMetadataWithTotalCount
        collection_metadata_with_total_count_model[
            "collectionType"
        ] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_with_total_count_model["collectionTotal"] = 1
        collection_metadata_with_total_count_model["totalCount"] = 1

        kmip_profile_data_body_model = {}  # KMIPProfileDataBodyKMIPProfileDataNative
        kmip_profile_data_body_model["crk_id"] = "feddecaf-0000-0000-0000-1234567890ab"

        kmip_adapter_model = {}  # KMIPAdapter
        kmip_adapter_model["id"] = "feddecaf-0000-0000-0000-1234567890ab"
        kmip_adapter_model["name"] = "kmip-adapter-name"
        kmip_adapter_model["created_at"] = "2019-01-01T12:00:00Z"
        kmip_adapter_model["created_by"] = "testString"
        kmip_adapter_model["updated_at"] = "2019-01-01T12:00:00Z"
        kmip_adapter_model["updated_by"] = "testString"
        kmip_adapter_model["profile"] = "native_1.0"
        kmip_adapter_model["description"] = "kmip adapter description"
        kmip_adapter_model["profile_data"] = kmip_profile_data_body_model

        # Construct a json representation of a ListKMIPAdaptersWithTotalCount model
        list_kmip_adapters_with_total_count_model_json = {}
        list_kmip_adapters_with_total_count_model_json["metadata"] = collection_metadata_with_total_count_model
        list_kmip_adapters_with_total_count_model_json["resources"] = [kmip_adapter_model]

        # Construct a model instance of ListKMIPAdaptersWithTotalCount by calling from_dict on the json representation
        list_kmip_adapters_with_total_count_model = ListKMIPAdaptersWithTotalCount.from_dict(
            list_kmip_adapters_with_total_count_model_json
        )
        assert list_kmip_adapters_with_total_count_model != False

        # Construct a model instance of ListKMIPAdaptersWithTotalCount by calling from_dict on the json representation
        list_kmip_adapters_with_total_count_model_dict = ListKMIPAdaptersWithTotalCount.from_dict(
            list_kmip_adapters_with_total_count_model_json
        ).__dict__
        list_kmip_adapters_with_total_count_model2 = ListKMIPAdaptersWithTotalCount(
            **list_kmip_adapters_with_total_count_model_dict
        )

        # Verify the model instances are equivalent
        assert list_kmip_adapters_with_total_count_model == list_kmip_adapters_with_total_count_model2

        # Convert model instance back to dict and verify no loss of data
        list_kmip_adapters_with_total_count_model_json2 = list_kmip_adapters_with_total_count_model.to_dict()
        assert list_kmip_adapters_with_total_count_model_json2 == list_kmip_adapters_with_total_count_model_json


class TestModel_ListKMIPClientCertificates:
    """
    Test Class for ListKMIPClientCertificates
    """

    def test_list_kmip_client_certificates_serialization(self):
        """
        Test serialization/deserialization for ListKMIPClientCertificates
        """

        # Construct dict forms of any model objects needed in order to build this model.

        list_collection_metadata_model = {}  # ListCollectionMetadataCollectionMetadataWithTotalCount
        list_collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        list_collection_metadata_model["collectionTotal"] = 1
        list_collection_metadata_model["totalCount"] = 1

        kmip_client_certificate_model = {}  # KMIPClientCertificate
        kmip_client_certificate_model["name"] = "testString"
        kmip_client_certificate_model["id"] = "feddecaf-0000-0000-0000-1234567890ab"
        kmip_client_certificate_model["created_at"] = "2019-01-01T12:00:00Z"
        kmip_client_certificate_model["created_by"] = "testString"
        kmip_client_certificate_model["certificate"] = "testString"

        # Construct a json representation of a ListKMIPClientCertificates model
        list_kmip_client_certificates_model_json = {}
        list_kmip_client_certificates_model_json["metadata"] = list_collection_metadata_model
        list_kmip_client_certificates_model_json["resources"] = [kmip_client_certificate_model]

        # Construct a model instance of ListKMIPClientCertificates by calling from_dict on the json representation
        list_kmip_client_certificates_model = ListKMIPClientCertificates.from_dict(
            list_kmip_client_certificates_model_json
        )
        assert list_kmip_client_certificates_model != False

        # Construct a model instance of ListKMIPClientCertificates by calling from_dict on the json representation
        list_kmip_client_certificates_model_dict = ListKMIPClientCertificates.from_dict(
            list_kmip_client_certificates_model_json
        ).__dict__
        list_kmip_client_certificates_model2 = ListKMIPClientCertificates(**list_kmip_client_certificates_model_dict)

        # Verify the model instances are equivalent
        assert list_kmip_client_certificates_model == list_kmip_client_certificates_model2

        # Convert model instance back to dict and verify no loss of data
        list_kmip_client_certificates_model_json2 = list_kmip_client_certificates_model.to_dict()
        assert list_kmip_client_certificates_model_json2 == list_kmip_client_certificates_model_json


class TestModel_ListKMIPObjectsWithTotalCount:
    """
    Test Class for ListKMIPObjectsWithTotalCount
    """

    def test_list_kmip_objects_with_total_count_serialization(self):
        """
        Test serialization/deserialization for ListKMIPObjectsWithTotalCount
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_with_total_count_model = {}  # CollectionMetadataWithTotalCount
        collection_metadata_with_total_count_model[
            "collectionType"
        ] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_with_total_count_model["collectionTotal"] = 1
        collection_metadata_with_total_count_model["totalCount"] = 1

        kmip_object_model = {}  # KMIPObject
        kmip_object_model["id"] = "feddecaf-0000-0000-0000-1234567890ab"
        kmip_object_model["kmip_object_type"] = 2
        kmip_object_model["state"] = 1
        kmip_object_model["created_at"] = "2019-01-01T12:00:00Z"
        kmip_object_model["created_by_kmip_client_cert_id"] = "feddecaf-0000-0000-0000-1234567890ab"
        kmip_object_model["created_by"] = "testString"
        kmip_object_model["updated_at"] = "2019-01-01T12:00:00Z"
        kmip_object_model["updated_by_kmip_client_cert_id"] = "feddecaf-0000-0000-0000-1234567890ab"
        kmip_object_model["updated_by"] = "testString"
        kmip_object_model["destroyed_at"] = "2019-01-01T12:00:00Z"
        kmip_object_model["destroyed_by_kmip_client_cert_id"] = "feddecaf-0000-0000-0000-1234567890ab"
        kmip_object_model["destroyed_by"] = "testString"
        kmip_object_model["recoverable"] = True

        # Construct a json representation of a ListKMIPObjectsWithTotalCount model
        list_kmip_objects_with_total_count_model_json = {}
        list_kmip_objects_with_total_count_model_json["metadata"] = collection_metadata_with_total_count_model
        list_kmip_objects_with_total_count_model_json["resources"] = [kmip_object_model]

        # Construct a model instance of ListKMIPObjectsWithTotalCount by calling from_dict on the json representation
        list_kmip_objects_with_total_count_model = ListKMIPObjectsWithTotalCount.from_dict(
            list_kmip_objects_with_total_count_model_json
        )
        assert list_kmip_objects_with_total_count_model != False

        # Construct a model instance of ListKMIPObjectsWithTotalCount by calling from_dict on the json representation
        list_kmip_objects_with_total_count_model_dict = ListKMIPObjectsWithTotalCount.from_dict(
            list_kmip_objects_with_total_count_model_json
        ).__dict__
        list_kmip_objects_with_total_count_model2 = ListKMIPObjectsWithTotalCount(
            **list_kmip_objects_with_total_count_model_dict
        )

        # Verify the model instances are equivalent
        assert list_kmip_objects_with_total_count_model == list_kmip_objects_with_total_count_model2

        # Convert model instance back to dict and verify no loss of data
        list_kmip_objects_with_total_count_model_json2 = list_kmip_objects_with_total_count_model.to_dict()
        assert list_kmip_objects_with_total_count_model_json2 == list_kmip_objects_with_total_count_model_json


class TestModel_ListKMIPPartialClientCertificatesWithTotalCount:
    """
    Test Class for ListKMIPPartialClientCertificatesWithTotalCount
    """

    def test_list_kmip_partial_client_certificates_with_total_count_serialization(self):
        """
        Test serialization/deserialization for ListKMIPPartialClientCertificatesWithTotalCount
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_with_total_count_model = {}  # CollectionMetadataWithTotalCount
        collection_metadata_with_total_count_model[
            "collectionType"
        ] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_with_total_count_model["collectionTotal"] = 1
        collection_metadata_with_total_count_model["totalCount"] = 1

        kmip_client_partial_certificate_model = {}  # KMIPClientPartialCertificate
        kmip_client_partial_certificate_model["name"] = "testString"
        kmip_client_partial_certificate_model["id"] = "feddecaf-0000-0000-0000-1234567890ab"
        kmip_client_partial_certificate_model["created_at"] = "2019-01-01T12:00:00Z"
        kmip_client_partial_certificate_model["created_by"] = "testString"

        # Construct a json representation of a ListKMIPPartialClientCertificatesWithTotalCount model
        list_kmip_partial_client_certificates_with_total_count_model_json = {}
        list_kmip_partial_client_certificates_with_total_count_model_json[
            "metadata"
        ] = collection_metadata_with_total_count_model
        list_kmip_partial_client_certificates_with_total_count_model_json["resources"] = [
            kmip_client_partial_certificate_model
        ]

        # Construct a model instance of ListKMIPPartialClientCertificatesWithTotalCount by calling from_dict on the json representation
        list_kmip_partial_client_certificates_with_total_count_model = (
            ListKMIPPartialClientCertificatesWithTotalCount.from_dict(
                list_kmip_partial_client_certificates_with_total_count_model_json
            )
        )
        assert list_kmip_partial_client_certificates_with_total_count_model != False

        # Construct a model instance of ListKMIPPartialClientCertificatesWithTotalCount by calling from_dict on the json representation
        list_kmip_partial_client_certificates_with_total_count_model_dict = (
            ListKMIPPartialClientCertificatesWithTotalCount.from_dict(
                list_kmip_partial_client_certificates_with_total_count_model_json
            ).__dict__
        )
        list_kmip_partial_client_certificates_with_total_count_model2 = ListKMIPPartialClientCertificatesWithTotalCount(
            **list_kmip_partial_client_certificates_with_total_count_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            list_kmip_partial_client_certificates_with_total_count_model
            == list_kmip_partial_client_certificates_with_total_count_model2
        )

        # Convert model instance back to dict and verify no loss of data
        list_kmip_partial_client_certificates_with_total_count_model_json2 = (
            list_kmip_partial_client_certificates_with_total_count_model.to_dict()
        )
        assert (
            list_kmip_partial_client_certificates_with_total_count_model_json2
            == list_kmip_partial_client_certificates_with_total_count_model_json
        )


class TestModel_ListKeyRingsWithTotalCount:
    """
    Test Class for ListKeyRingsWithTotalCount
    """

    def test_list_key_rings_with_total_count_serialization(self):
        """
        Test serialization/deserialization for ListKeyRingsWithTotalCount
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_with_total_count_model = {}  # CollectionMetadataWithTotalCount
        collection_metadata_with_total_count_model[
            "collectionType"
        ] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_with_total_count_model["collectionTotal"] = 1
        collection_metadata_with_total_count_model["totalCount"] = 1

        key_ring_model = {}  # KeyRing
        key_ring_model["id"] = "testString"
        key_ring_model["creationDate"] = "2000-03-21T00:00:00Z"
        key_ring_model["createdBy"] = "testString"

        # Construct a json representation of a ListKeyRingsWithTotalCount model
        list_key_rings_with_total_count_model_json = {}
        list_key_rings_with_total_count_model_json["metadata"] = collection_metadata_with_total_count_model
        list_key_rings_with_total_count_model_json["resources"] = [key_ring_model]

        # Construct a model instance of ListKeyRingsWithTotalCount by calling from_dict on the json representation
        list_key_rings_with_total_count_model = ListKeyRingsWithTotalCount.from_dict(
            list_key_rings_with_total_count_model_json
        )
        assert list_key_rings_with_total_count_model != False

        # Construct a model instance of ListKeyRingsWithTotalCount by calling from_dict on the json representation
        list_key_rings_with_total_count_model_dict = ListKeyRingsWithTotalCount.from_dict(
            list_key_rings_with_total_count_model_json
        ).__dict__
        list_key_rings_with_total_count_model2 = ListKeyRingsWithTotalCount(
            **list_key_rings_with_total_count_model_dict
        )

        # Verify the model instances are equivalent
        assert list_key_rings_with_total_count_model == list_key_rings_with_total_count_model2

        # Convert model instance back to dict and verify no loss of data
        list_key_rings_with_total_count_model_json2 = list_key_rings_with_total_count_model.to_dict()
        assert list_key_rings_with_total_count_model_json2 == list_key_rings_with_total_count_model_json


class TestModel_ListKeyVersions:
    """
    Test Class for ListKeyVersions
    """

    def test_list_key_versions_serialization(self):
        """
        Test serialization/deserialization for ListKeyVersions
        """

        # Construct dict forms of any model objects needed in order to build this model.

        list_collection_metadata_model = {}  # ListCollectionMetadataCollectionMetadataWithTotalCount
        list_collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        list_collection_metadata_model["collectionTotal"] = 1
        list_collection_metadata_model["totalCount"] = 1

        key_version_model = {}  # KeyVersion

        # Construct a json representation of a ListKeyVersions model
        list_key_versions_model_json = {}
        list_key_versions_model_json["metadata"] = list_collection_metadata_model
        list_key_versions_model_json["resources"] = [key_version_model]

        # Construct a model instance of ListKeyVersions by calling from_dict on the json representation
        list_key_versions_model = ListKeyVersions.from_dict(list_key_versions_model_json)
        assert list_key_versions_model != False

        # Construct a model instance of ListKeyVersions by calling from_dict on the json representation
        list_key_versions_model_dict = ListKeyVersions.from_dict(list_key_versions_model_json).__dict__
        list_key_versions_model2 = ListKeyVersions(**list_key_versions_model_dict)

        # Verify the model instances are equivalent
        assert list_key_versions_model == list_key_versions_model2

        # Convert model instance back to dict and verify no loss of data
        list_key_versions_model_json2 = list_key_versions_model.to_dict()
        assert list_key_versions_model_json2 == list_key_versions_model_json


class TestModel_ListKeys:
    """
    Test Class for ListKeys
    """

    def test_list_keys_serialization(self):
        """
        Test serialization/deserialization for ListKeys
        """

        # Construct dict forms of any model objects needed in order to build this model.

        list_keys_metadata_properties_search_query_model = {}  # ListKeysMetadataPropertiesSearchQuery
        list_keys_metadata_properties_search_query_model["query"] = "testString"
        list_keys_metadata_properties_search_query_model["scopes"] = ["name"]
        list_keys_metadata_properties_search_query_model["not"] = True
        list_keys_metadata_properties_search_query_model["exact"] = True

        collection_metadata_list_keys_model = {}  # CollectionMetadataListKeys
        collection_metadata_list_keys_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_list_keys_model["collectionTotal"] = 1
        collection_metadata_list_keys_model["incompleteSearch"] = True
        collection_metadata_list_keys_model["searchQuery"] = list_keys_metadata_properties_search_query_model

        dual_auth_key_metadata_model = {}  # DualAuthKeyMetadata
        dual_auth_key_metadata_model["enabled"] = True
        dual_auth_key_metadata_model["keySetForDeletion"] = True

        rotation_key_metadata_model = {}  # RotationKeyMetadata
        rotation_key_metadata_model["enabled"] = True
        rotation_key_metadata_model["interval_month"] = 3

        key_full_representation_model = {}  # KeyFullRepresentation
        key_full_representation_model["type"] = "application/vnd.ibm.kms.key+json"
        key_full_representation_model["name"] = "testString"
        key_full_representation_model["aliases"] = ["testString"]
        key_full_representation_model["description"] = "testString"
        key_full_representation_model["tags"] = ["testString"]
        key_full_representation_model["extractable"] = True
        key_full_representation_model["keyRingID"] = "testString"
        key_full_representation_model["algorithmBitSize"] = 256
        key_full_representation_model["algorithmMode"] = "CBC_PAD"
        key_full_representation_model["dualAuthDelete"] = dual_auth_key_metadata_model
        key_full_representation_model["rotation"] = rotation_key_metadata_model
        key_full_representation_model["restoreExpirationDate"] = "2000-03-21T00:00:00Z"
        key_full_representation_model["restoreAllowed"] = True
        key_full_representation_model["purgeAllowed"] = True
        key_full_representation_model["purgeAllowedFrom"] = "2000-03-21T00:00:00Z"
        key_full_representation_model["purgeScheduledOn"] = "2000-03-21T00:00:00Z"

        # Construct a json representation of a ListKeys model
        list_keys_model_json = {}
        list_keys_model_json["metadata"] = collection_metadata_list_keys_model
        list_keys_model_json["resources"] = [key_full_representation_model]

        # Construct a model instance of ListKeys by calling from_dict on the json representation
        list_keys_model = ListKeys.from_dict(list_keys_model_json)
        assert list_keys_model != False

        # Construct a model instance of ListKeys by calling from_dict on the json representation
        list_keys_model_dict = ListKeys.from_dict(list_keys_model_json).__dict__
        list_keys_model2 = ListKeys(**list_keys_model_dict)

        # Verify the model instances are equivalent
        assert list_keys_model == list_keys_model2

        # Convert model instance back to dict and verify no loss of data
        list_keys_model_json2 = list_keys_model.to_dict()
        assert list_keys_model_json2 == list_keys_model_json


class TestModel_ListKeysMetadataPropertiesSearchQuery:
    """
    Test Class for ListKeysMetadataPropertiesSearchQuery
    """

    def test_list_keys_metadata_properties_search_query_serialization(self):
        """
        Test serialization/deserialization for ListKeysMetadataPropertiesSearchQuery
        """

        # Construct a json representation of a ListKeysMetadataPropertiesSearchQuery model
        list_keys_metadata_properties_search_query_model_json = {}
        list_keys_metadata_properties_search_query_model_json["query"] = "testString"
        list_keys_metadata_properties_search_query_model_json["scopes"] = ["name"]
        list_keys_metadata_properties_search_query_model_json["not"] = True
        list_keys_metadata_properties_search_query_model_json["exact"] = True

        # Construct a model instance of ListKeysMetadataPropertiesSearchQuery by calling from_dict on the json representation
        list_keys_metadata_properties_search_query_model = ListKeysMetadataPropertiesSearchQuery.from_dict(
            list_keys_metadata_properties_search_query_model_json
        )
        assert list_keys_metadata_properties_search_query_model != False

        # Construct a model instance of ListKeysMetadataPropertiesSearchQuery by calling from_dict on the json representation
        list_keys_metadata_properties_search_query_model_dict = ListKeysMetadataPropertiesSearchQuery.from_dict(
            list_keys_metadata_properties_search_query_model_json
        ).__dict__
        list_keys_metadata_properties_search_query_model2 = ListKeysMetadataPropertiesSearchQuery(
            **list_keys_metadata_properties_search_query_model_dict
        )

        # Verify the model instances are equivalent
        assert list_keys_metadata_properties_search_query_model == list_keys_metadata_properties_search_query_model2

        # Convert model instance back to dict and verify no loss of data
        list_keys_metadata_properties_search_query_model_json2 = (
            list_keys_metadata_properties_search_query_model.to_dict()
        )
        assert (
            list_keys_metadata_properties_search_query_model_json2
            == list_keys_metadata_properties_search_query_model_json
        )


class TestModel_MetricsProperties:
    """
    Test Class for MetricsProperties
    """

    def test_metrics_properties_serialization(self):
        """
        Test serialization/deserialization for MetricsProperties
        """

        # Construct a json representation of a MetricsProperties model
        metrics_properties_model_json = {}
        metrics_properties_model_json["enabled"] = True

        # Construct a model instance of MetricsProperties by calling from_dict on the json representation
        metrics_properties_model = MetricsProperties.from_dict(metrics_properties_model_json)
        assert metrics_properties_model != False

        # Construct a model instance of MetricsProperties by calling from_dict on the json representation
        metrics_properties_model_dict = MetricsProperties.from_dict(metrics_properties_model_json).__dict__
        metrics_properties_model2 = MetricsProperties(**metrics_properties_model_dict)

        # Verify the model instances are equivalent
        assert metrics_properties_model == metrics_properties_model2

        # Convert model instance back to dict and verify no loss of data
        metrics_properties_model_json2 = metrics_properties_model.to_dict()
        assert metrics_properties_model_json2 == metrics_properties_model_json


class TestModel_PatchKeyResponseBody:
    """
    Test Class for PatchKeyResponseBody
    """

    def test_patch_key_response_body_serialization(self):
        """
        Test serialization/deserialization for PatchKeyResponseBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        dual_auth_key_metadata_model = {}  # DualAuthKeyMetadata
        dual_auth_key_metadata_model["enabled"] = True
        dual_auth_key_metadata_model["keySetForDeletion"] = True

        rotation_key_metadata_model = {}  # RotationKeyMetadata
        rotation_key_metadata_model["enabled"] = True
        rotation_key_metadata_model["interval_month"] = 3

        key_full_representation_model = {}  # KeyFullRepresentation
        key_full_representation_model["type"] = "application/vnd.ibm.kms.key+json"
        key_full_representation_model["name"] = "testString"
        key_full_representation_model["aliases"] = ["testString"]
        key_full_representation_model["description"] = "testString"
        key_full_representation_model["tags"] = ["testString"]
        key_full_representation_model["extractable"] = True
        key_full_representation_model["keyRingID"] = "testString"
        key_full_representation_model["algorithmBitSize"] = 256
        key_full_representation_model["algorithmMode"] = "CBC_PAD"
        key_full_representation_model["dualAuthDelete"] = dual_auth_key_metadata_model
        key_full_representation_model["rotation"] = rotation_key_metadata_model
        key_full_representation_model["restoreExpirationDate"] = "2000-03-21T00:00:00Z"
        key_full_representation_model["restoreAllowed"] = True
        key_full_representation_model["purgeAllowed"] = True
        key_full_representation_model["purgeAllowedFrom"] = "2000-03-21T00:00:00Z"
        key_full_representation_model["purgeScheduledOn"] = "2000-03-21T00:00:00Z"

        # Construct a json representation of a PatchKeyResponseBody model
        patch_key_response_body_model_json = {}
        patch_key_response_body_model_json["metadata"] = collection_metadata_model
        patch_key_response_body_model_json["resources"] = [key_full_representation_model]

        # Construct a model instance of PatchKeyResponseBody by calling from_dict on the json representation
        patch_key_response_body_model = PatchKeyResponseBody.from_dict(patch_key_response_body_model_json)
        assert patch_key_response_body_model != False

        # Construct a model instance of PatchKeyResponseBody by calling from_dict on the json representation
        patch_key_response_body_model_dict = PatchKeyResponseBody.from_dict(patch_key_response_body_model_json).__dict__
        patch_key_response_body_model2 = PatchKeyResponseBody(**patch_key_response_body_model_dict)

        # Verify the model instances are equivalent
        assert patch_key_response_body_model == patch_key_response_body_model2

        # Convert model instance back to dict and verify no loss of data
        patch_key_response_body_model_json2 = patch_key_response_body_model.to_dict()
        assert patch_key_response_body_model_json2 == patch_key_response_body_model_json


class TestModel_PurgeKey:
    """
    Test Class for PurgeKey
    """

    def test_purge_key_serialization(self):
        """
        Test serialization/deserialization for PurgeKey
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        dual_auth_key_metadata_model = {}  # DualAuthKeyMetadata
        dual_auth_key_metadata_model["enabled"] = True
        dual_auth_key_metadata_model["keySetForDeletion"] = True

        rotation_key_metadata_model = {}  # RotationKeyMetadata
        rotation_key_metadata_model["enabled"] = True
        rotation_key_metadata_model["interval_month"] = 3

        key_full_representation_model = {}  # KeyFullRepresentation
        key_full_representation_model["type"] = "application/vnd.ibm.kms.key+json"
        key_full_representation_model["name"] = "testString"
        key_full_representation_model["aliases"] = ["testString"]
        key_full_representation_model["description"] = "testString"
        key_full_representation_model["tags"] = ["testString"]
        key_full_representation_model["extractable"] = True
        key_full_representation_model["keyRingID"] = "testString"
        key_full_representation_model["algorithmBitSize"] = 256
        key_full_representation_model["algorithmMode"] = "CBC_PAD"
        key_full_representation_model["dualAuthDelete"] = dual_auth_key_metadata_model
        key_full_representation_model["rotation"] = rotation_key_metadata_model
        key_full_representation_model["restoreExpirationDate"] = "2000-03-21T00:00:00Z"
        key_full_representation_model["restoreAllowed"] = True
        key_full_representation_model["purgeAllowed"] = True
        key_full_representation_model["purgeAllowedFrom"] = "2000-03-21T00:00:00Z"
        key_full_representation_model["purgeScheduledOn"] = "2000-03-21T00:00:00Z"

        # Construct a json representation of a PurgeKey model
        purge_key_model_json = {}
        purge_key_model_json["metadata"] = collection_metadata_model
        purge_key_model_json["resources"] = [key_full_representation_model]

        # Construct a model instance of PurgeKey by calling from_dict on the json representation
        purge_key_model = PurgeKey.from_dict(purge_key_model_json)
        assert purge_key_model != False

        # Construct a model instance of PurgeKey by calling from_dict on the json representation
        purge_key_model_dict = PurgeKey.from_dict(purge_key_model_json).__dict__
        purge_key_model2 = PurgeKey(**purge_key_model_dict)

        # Verify the model instances are equivalent
        assert purge_key_model == purge_key_model2

        # Convert model instance back to dict and verify no loss of data
        purge_key_model_json2 = purge_key_model.to_dict()
        assert purge_key_model_json2 == purge_key_model_json


class TestModel_RegistrationResource:
    """
    Test Class for RegistrationResource
    """

    def test_registration_resource_serialization(self):
        """
        Test serialization/deserialization for RegistrationResource
        """

        # Construct a json representation of a RegistrationResource model
        registration_resource_model_json = {}

        # Construct a model instance of RegistrationResource by calling from_dict on the json representation
        registration_resource_model = RegistrationResource.from_dict(registration_resource_model_json)
        assert registration_resource_model != False

        # Construct a model instance of RegistrationResource by calling from_dict on the json representation
        registration_resource_model_dict = RegistrationResource.from_dict(registration_resource_model_json).__dict__
        registration_resource_model2 = RegistrationResource(**registration_resource_model_dict)

        # Verify the model instances are equivalent
        assert registration_resource_model == registration_resource_model2

        # Convert model instance back to dict and verify no loss of data
        registration_resource_model_json2 = registration_resource_model.to_dict()
        assert registration_resource_model_json2 == registration_resource_model_json


class TestModel_RegistrationWithTotalCount:
    """
    Test Class for RegistrationWithTotalCount
    """

    def test_registration_with_total_count_serialization(self):
        """
        Test serialization/deserialization for RegistrationWithTotalCount
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_with_total_count_model = {}  # CollectionMetadataWithTotalCount
        collection_metadata_with_total_count_model[
            "collectionType"
        ] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_with_total_count_model["collectionTotal"] = 1
        collection_metadata_with_total_count_model["totalCount"] = 1

        registration_resource_model = {}  # RegistrationResource

        # Construct a json representation of a RegistrationWithTotalCount model
        registration_with_total_count_model_json = {}
        registration_with_total_count_model_json["metadata"] = collection_metadata_with_total_count_model
        registration_with_total_count_model_json["resources"] = [registration_resource_model]

        # Construct a model instance of RegistrationWithTotalCount by calling from_dict on the json representation
        registration_with_total_count_model = RegistrationWithTotalCount.from_dict(
            registration_with_total_count_model_json
        )
        assert registration_with_total_count_model != False

        # Construct a model instance of RegistrationWithTotalCount by calling from_dict on the json representation
        registration_with_total_count_model_dict = RegistrationWithTotalCount.from_dict(
            registration_with_total_count_model_json
        ).__dict__
        registration_with_total_count_model2 = RegistrationWithTotalCount(**registration_with_total_count_model_dict)

        # Verify the model instances are equivalent
        assert registration_with_total_count_model == registration_with_total_count_model2

        # Convert model instance back to dict and verify no loss of data
        registration_with_total_count_model_json2 = registration_with_total_count_model.to_dict()
        assert registration_with_total_count_model_json2 == registration_with_total_count_model_json


class TestModel_RewrapKeyResponseBody:
    """
    Test Class for RewrapKeyResponseBody
    """

    def test_rewrap_key_response_body_serialization(self):
        """
        Test serialization/deserialization for RewrapKeyResponseBody
        """

        # Construct a json representation of a RewrapKeyResponseBody model
        rewrap_key_response_body_model_json = {}
        rewrap_key_response_body_model_json["ciphertext"] = "testString"

        # Construct a model instance of RewrapKeyResponseBody by calling from_dict on the json representation
        rewrap_key_response_body_model = RewrapKeyResponseBody.from_dict(rewrap_key_response_body_model_json)
        assert rewrap_key_response_body_model != False

        # Construct a model instance of RewrapKeyResponseBody by calling from_dict on the json representation
        rewrap_key_response_body_model_dict = RewrapKeyResponseBody.from_dict(
            rewrap_key_response_body_model_json
        ).__dict__
        rewrap_key_response_body_model2 = RewrapKeyResponseBody(**rewrap_key_response_body_model_dict)

        # Verify the model instances are equivalent
        assert rewrap_key_response_body_model == rewrap_key_response_body_model2

        # Convert model instance back to dict and verify no loss of data
        rewrap_key_response_body_model_json2 = rewrap_key_response_body_model.to_dict()
        assert rewrap_key_response_body_model_json2 == rewrap_key_response_body_model_json


class TestModel_RewrappedKeyVersionRewrappedKeyVersion:
    """
    Test Class for RewrappedKeyVersionRewrappedKeyVersion
    """

    def test_rewrapped_key_version_rewrapped_key_version_serialization(self):
        """
        Test serialization/deserialization for RewrappedKeyVersionRewrappedKeyVersion
        """

        # Construct a json representation of a RewrappedKeyVersionRewrappedKeyVersion model
        rewrapped_key_version_rewrapped_key_version_model_json = {}

        # Construct a model instance of RewrappedKeyVersionRewrappedKeyVersion by calling from_dict on the json representation
        rewrapped_key_version_rewrapped_key_version_model = RewrappedKeyVersionRewrappedKeyVersion.from_dict(
            rewrapped_key_version_rewrapped_key_version_model_json
        )
        assert rewrapped_key_version_rewrapped_key_version_model != False

        # Construct a model instance of RewrappedKeyVersionRewrappedKeyVersion by calling from_dict on the json representation
        rewrapped_key_version_rewrapped_key_version_model_dict = RewrappedKeyVersionRewrappedKeyVersion.from_dict(
            rewrapped_key_version_rewrapped_key_version_model_json
        ).__dict__
        rewrapped_key_version_rewrapped_key_version_model2 = RewrappedKeyVersionRewrappedKeyVersion(
            **rewrapped_key_version_rewrapped_key_version_model_dict
        )

        # Verify the model instances are equivalent
        assert rewrapped_key_version_rewrapped_key_version_model == rewrapped_key_version_rewrapped_key_version_model2

        # Convert model instance back to dict and verify no loss of data
        rewrapped_key_version_rewrapped_key_version_model_json2 = (
            rewrapped_key_version_rewrapped_key_version_model.to_dict()
        )
        assert (
            rewrapped_key_version_rewrapped_key_version_model_json2
            == rewrapped_key_version_rewrapped_key_version_model_json
        )


class TestModel_RotationKeyMetadata:
    """
    Test Class for RotationKeyMetadata
    """

    def test_rotation_key_metadata_serialization(self):
        """
        Test serialization/deserialization for RotationKeyMetadata
        """

        # Construct a json representation of a RotationKeyMetadata model
        rotation_key_metadata_model_json = {}
        rotation_key_metadata_model_json["enabled"] = True
        rotation_key_metadata_model_json["interval_month"] = 3

        # Construct a model instance of RotationKeyMetadata by calling from_dict on the json representation
        rotation_key_metadata_model = RotationKeyMetadata.from_dict(rotation_key_metadata_model_json)
        assert rotation_key_metadata_model != False

        # Construct a model instance of RotationKeyMetadata by calling from_dict on the json representation
        rotation_key_metadata_model_dict = RotationKeyMetadata.from_dict(rotation_key_metadata_model_json).__dict__
        rotation_key_metadata_model2 = RotationKeyMetadata(**rotation_key_metadata_model_dict)

        # Verify the model instances are equivalent
        assert rotation_key_metadata_model == rotation_key_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        rotation_key_metadata_model_json2 = rotation_key_metadata_model.to_dict()
        assert rotation_key_metadata_model_json2 == rotation_key_metadata_model_json


class TestModel_SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem:
    """
    Test Class for SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem
    """

    def test_set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_serialization(
        self,
    ):
        """
        Test serialization/deserialization for SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        instance_policy_allowed_ip_policy_data_attributes_model = {}  # InstancePolicyAllowedIPPolicyDataAttributes
        instance_policy_allowed_ip_policy_data_attributes_model["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]

        instance_policy_allowed_ip_policy_data_model = {}  # InstancePolicyAllowedIPPolicyData
        instance_policy_allowed_ip_policy_data_model["enabled"] = True
        instance_policy_allowed_ip_policy_data_model[
            "attributes"
        ] = instance_policy_allowed_ip_policy_data_attributes_model

        # Construct a json representation of a SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem model
        set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model_json = {}
        set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model_json[
            "policy_type"
        ] = "allowedIP"
        set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model_json[
            "policy_data"
        ] = instance_policy_allowed_ip_policy_data_model

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model = (
            SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem.from_dict(
                set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model_json
            )
        )
        assert set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model != False

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model_dict = (
            SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem.from_dict(
                set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model_json
            ).__dict__
        )
        set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model2 = (
            SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem(
                **set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model
            == set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model_json2 = (
            set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model.to_dict()
        )
        assert (
            set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model_json2
            == set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model_json
        )


class TestModel_SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem:
    """
    Test Class for SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem
    """

    def test_set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_serialization(
        self,
    ):
        """
        Test serialization/deserialization for SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        instance_policy_allowed_network_policy_data_attributes_model = (
            {}
        )  # InstancePolicyAllowedNetworkPolicyDataAttributes
        instance_policy_allowed_network_policy_data_attributes_model["allowed_network"] = "public-and-private"

        instance_policy_allowed_network_policy_data_model = {}  # InstancePolicyAllowedNetworkPolicyData
        instance_policy_allowed_network_policy_data_model["enabled"] = True
        instance_policy_allowed_network_policy_data_model[
            "attributes"
        ] = instance_policy_allowed_network_policy_data_attributes_model

        # Construct a json representation of a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem model
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model_json = {}
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model_json[
            "policy_type"
        ] = "allowedNetwork"
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model_json[
            "policy_data"
        ] = instance_policy_allowed_network_policy_data_model

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model = (
            SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem.from_dict(
                set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model_json
            )
        )
        assert set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model != False

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model_dict = (
            SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem.from_dict(
                set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model_json
            ).__dict__
        )
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model2 = (
            SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem(
                **set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model
            == set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model_json2 = (
            set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model.to_dict()
        )
        assert (
            set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model_json2
            == set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model_json
        )


class TestModel_SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem:
    """
    Test Class for SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem
    """

    def test_set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_serialization(
        self,
    ):
        """
        Test serialization/deserialization for SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        instance_policy_key_create_import_access_policy_data_attributes_model = (
            {}
        )  # InstancePolicyKeyCreateImportAccessPolicyDataAttributes
        instance_policy_key_create_import_access_policy_data_attributes_model["create_root_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model["create_standard_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model["import_root_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model["import_standard_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model["enforce_token"] = True

        instance_policy_key_create_import_access_policy_data_model = {}  # InstancePolicyKeyCreateImportAccessPolicyData
        instance_policy_key_create_import_access_policy_data_model["enabled"] = True
        instance_policy_key_create_import_access_policy_data_model[
            "attributes"
        ] = instance_policy_key_create_import_access_policy_data_attributes_model

        # Construct a json representation of a SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem model
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model_json = {}
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model_json[
            "policy_type"
        ] = "keyCreateImportAccess"
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model_json[
            "policy_data"
        ] = instance_policy_key_create_import_access_policy_data_model

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model = (
            SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem.from_dict(
                set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model_json
            )
        )
        assert set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model != False

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model_dict = (
            SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem.from_dict(
                set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model_json
            ).__dict__
        )
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model2 = (
            SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem(
                **set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model
            == set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model_json2 = (
            set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model.to_dict()
        )
        assert (
            set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model_json2
            == set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model_json
        )


class TestModel_SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem:
    """
    Test Class for SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem
    """

    def test_set_instance_policies_one_of_set_instance_policy_metrics_resources_item_serialization(
        self,
    ):
        """
        Test serialization/deserialization for SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        metrics_properties_model = {}  # MetricsProperties
        metrics_properties_model["enabled"] = True

        # Construct a json representation of a SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem model
        set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model_json = {}
        set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model_json["policy_type"] = "metrics"
        set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model_json[
            "policy_data"
        ] = metrics_properties_model

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model = (
            SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem.from_dict(
                set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model_json
            )
        )
        assert set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model != False

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model_dict = (
            SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem.from_dict(
                set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model_json
            ).__dict__
        )
        set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model2 = (
            SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem(
                **set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model
            == set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model_json2 = (
            set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model.to_dict()
        )
        assert (
            set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model_json2
            == set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model_json
        )


class TestModel_SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem:
    """
    Test Class for SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem
    """

    def test_set_instance_policies_one_of_set_instance_policy_rotation_resources_item_serialization(
        self,
    ):
        """
        Test serialization/deserialization for SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        instance_policy_rotation_policy_data_attributes_model = {}  # InstancePolicyRotationPolicyDataAttributes
        instance_policy_rotation_policy_data_attributes_model["interval_month"] = 3

        instance_policy_rotation_policy_data_model = {}  # InstancePolicyRotationPolicyData
        instance_policy_rotation_policy_data_model["enabled"] = True
        instance_policy_rotation_policy_data_model["attributes"] = instance_policy_rotation_policy_data_attributes_model

        # Construct a json representation of a SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem model
        set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model_json = {}
        set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model_json["policy_type"] = "rotation"
        set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model_json[
            "policy_data"
        ] = instance_policy_rotation_policy_data_model

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model = (
            SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem.from_dict(
                set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model_json
            )
        )
        assert set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model != False

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model_dict = (
            SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem.from_dict(
                set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model_json
            ).__dict__
        )
        set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model2 = (
            SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem(
                **set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model
            == set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model_json2 = (
            set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model.to_dict()
        )
        assert (
            set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model_json2
            == set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model_json
        )


class TestModel_SetInstancePolicyDualAuthDeleteResourcesItem:
    """
    Test Class for SetInstancePolicyDualAuthDeleteResourcesItem
    """

    def test_set_instance_policy_dual_auth_delete_resources_item_serialization(self):
        """
        Test serialization/deserialization for SetInstancePolicyDualAuthDeleteResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        dual_auth_delete_properties_model = {}  # DualAuthDeleteProperties
        dual_auth_delete_properties_model["enabled"] = True

        # Construct a json representation of a SetInstancePolicyDualAuthDeleteResourcesItem model
        set_instance_policy_dual_auth_delete_resources_item_model_json = {}
        set_instance_policy_dual_auth_delete_resources_item_model_json["policy_type"] = "dualAuthDelete"
        set_instance_policy_dual_auth_delete_resources_item_model_json[
            "policy_data"
        ] = dual_auth_delete_properties_model

        # Construct a model instance of SetInstancePolicyDualAuthDeleteResourcesItem by calling from_dict on the json representation
        set_instance_policy_dual_auth_delete_resources_item_model = (
            SetInstancePolicyDualAuthDeleteResourcesItem.from_dict(
                set_instance_policy_dual_auth_delete_resources_item_model_json
            )
        )
        assert set_instance_policy_dual_auth_delete_resources_item_model != False

        # Construct a model instance of SetInstancePolicyDualAuthDeleteResourcesItem by calling from_dict on the json representation
        set_instance_policy_dual_auth_delete_resources_item_model_dict = (
            SetInstancePolicyDualAuthDeleteResourcesItem.from_dict(
                set_instance_policy_dual_auth_delete_resources_item_model_json
            ).__dict__
        )
        set_instance_policy_dual_auth_delete_resources_item_model2 = SetInstancePolicyDualAuthDeleteResourcesItem(
            **set_instance_policy_dual_auth_delete_resources_item_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            set_instance_policy_dual_auth_delete_resources_item_model
            == set_instance_policy_dual_auth_delete_resources_item_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_instance_policy_dual_auth_delete_resources_item_model_json2 = (
            set_instance_policy_dual_auth_delete_resources_item_model.to_dict()
        )
        assert (
            set_instance_policy_dual_auth_delete_resources_item_model_json2
            == set_instance_policy_dual_auth_delete_resources_item_model_json
        )


class TestModel_SetMultipleInstancePoliciesResourcesItem:
    """
    Test Class for SetMultipleInstancePoliciesResourcesItem
    """

    def test_set_multiple_instance_policies_resources_item_serialization(self):
        """
        Test serialization/deserialization for SetMultipleInstancePoliciesResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        set_multiple_instance_policies_resources_item_policy_data_attributes_model = (
            {}
        )  # SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes
        set_multiple_instance_policies_resources_item_policy_data_attributes_model[
            "allowed_network"
        ] = "public-and-private"
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["create_root_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["create_standard_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["import_root_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["import_standard_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["enforce_token"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["interval_month"] = 3

        set_multiple_instance_policies_resources_item_policy_data_model = (
            {}
        )  # SetMultipleInstancePoliciesResourcesItemPolicyData
        set_multiple_instance_policies_resources_item_policy_data_model["enabled"] = True
        set_multiple_instance_policies_resources_item_policy_data_model[
            "attributes"
        ] = set_multiple_instance_policies_resources_item_policy_data_attributes_model

        # Construct a json representation of a SetMultipleInstancePoliciesResourcesItem model
        set_multiple_instance_policies_resources_item_model_json = {}
        set_multiple_instance_policies_resources_item_model_json["policy_type"] = "allowedNetwork"
        set_multiple_instance_policies_resources_item_model_json[
            "policy_data"
        ] = set_multiple_instance_policies_resources_item_policy_data_model

        # Construct a model instance of SetMultipleInstancePoliciesResourcesItem by calling from_dict on the json representation
        set_multiple_instance_policies_resources_item_model = SetMultipleInstancePoliciesResourcesItem.from_dict(
            set_multiple_instance_policies_resources_item_model_json
        )
        assert set_multiple_instance_policies_resources_item_model != False

        # Construct a model instance of SetMultipleInstancePoliciesResourcesItem by calling from_dict on the json representation
        set_multiple_instance_policies_resources_item_model_dict = SetMultipleInstancePoliciesResourcesItem.from_dict(
            set_multiple_instance_policies_resources_item_model_json
        ).__dict__
        set_multiple_instance_policies_resources_item_model2 = SetMultipleInstancePoliciesResourcesItem(
            **set_multiple_instance_policies_resources_item_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            set_multiple_instance_policies_resources_item_model == set_multiple_instance_policies_resources_item_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_multiple_instance_policies_resources_item_model_json2 = (
            set_multiple_instance_policies_resources_item_model.to_dict()
        )
        assert (
            set_multiple_instance_policies_resources_item_model_json2
            == set_multiple_instance_policies_resources_item_model_json
        )


class TestModel_SetMultipleInstancePoliciesResourcesItemPolicyData:
    """
    Test Class for SetMultipleInstancePoliciesResourcesItemPolicyData
    """

    def test_set_multiple_instance_policies_resources_item_policy_data_serialization(
        self,
    ):
        """
        Test serialization/deserialization for SetMultipleInstancePoliciesResourcesItemPolicyData
        """

        # Construct dict forms of any model objects needed in order to build this model.

        set_multiple_instance_policies_resources_item_policy_data_attributes_model = (
            {}
        )  # SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes
        set_multiple_instance_policies_resources_item_policy_data_attributes_model[
            "allowed_network"
        ] = "public-and-private"
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["create_root_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["create_standard_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["import_root_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["import_standard_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["enforce_token"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["interval_month"] = 3

        # Construct a json representation of a SetMultipleInstancePoliciesResourcesItemPolicyData model
        set_multiple_instance_policies_resources_item_policy_data_model_json = {}
        set_multiple_instance_policies_resources_item_policy_data_model_json["enabled"] = True
        set_multiple_instance_policies_resources_item_policy_data_model_json[
            "attributes"
        ] = set_multiple_instance_policies_resources_item_policy_data_attributes_model

        # Construct a model instance of SetMultipleInstancePoliciesResourcesItemPolicyData by calling from_dict on the json representation
        set_multiple_instance_policies_resources_item_policy_data_model = (
            SetMultipleInstancePoliciesResourcesItemPolicyData.from_dict(
                set_multiple_instance_policies_resources_item_policy_data_model_json
            )
        )
        assert set_multiple_instance_policies_resources_item_policy_data_model != False

        # Construct a model instance of SetMultipleInstancePoliciesResourcesItemPolicyData by calling from_dict on the json representation
        set_multiple_instance_policies_resources_item_policy_data_model_dict = (
            SetMultipleInstancePoliciesResourcesItemPolicyData.from_dict(
                set_multiple_instance_policies_resources_item_policy_data_model_json
            ).__dict__
        )
        set_multiple_instance_policies_resources_item_policy_data_model2 = (
            SetMultipleInstancePoliciesResourcesItemPolicyData(
                **set_multiple_instance_policies_resources_item_policy_data_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            set_multiple_instance_policies_resources_item_policy_data_model
            == set_multiple_instance_policies_resources_item_policy_data_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_multiple_instance_policies_resources_item_policy_data_model_json2 = (
            set_multiple_instance_policies_resources_item_policy_data_model.to_dict()
        )
        assert (
            set_multiple_instance_policies_resources_item_policy_data_model_json2
            == set_multiple_instance_policies_resources_item_policy_data_model_json
        )


class TestModel_SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes:
    """
    Test Class for SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes
    """

    def test_set_multiple_instance_policies_resources_item_policy_data_attributes_serialization(
        self,
    ):
        """
        Test serialization/deserialization for SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes
        """

        # Construct a json representation of a SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes model
        set_multiple_instance_policies_resources_item_policy_data_attributes_model_json = {}
        set_multiple_instance_policies_resources_item_policy_data_attributes_model_json[
            "allowed_network"
        ] = "public-and-private"
        set_multiple_instance_policies_resources_item_policy_data_attributes_model_json["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]
        set_multiple_instance_policies_resources_item_policy_data_attributes_model_json["create_root_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model_json["create_standard_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model_json["import_root_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model_json["import_standard_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model_json["enforce_token"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model_json["interval_month"] = 3

        # Construct a model instance of SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes by calling from_dict on the json representation
        set_multiple_instance_policies_resources_item_policy_data_attributes_model = (
            SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes.from_dict(
                set_multiple_instance_policies_resources_item_policy_data_attributes_model_json
            )
        )
        assert set_multiple_instance_policies_resources_item_policy_data_attributes_model != False

        # Construct a model instance of SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes by calling from_dict on the json representation
        set_multiple_instance_policies_resources_item_policy_data_attributes_model_dict = (
            SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes.from_dict(
                set_multiple_instance_policies_resources_item_policy_data_attributes_model_json
            ).__dict__
        )
        set_multiple_instance_policies_resources_item_policy_data_attributes_model2 = (
            SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes(
                **set_multiple_instance_policies_resources_item_policy_data_attributes_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            set_multiple_instance_policies_resources_item_policy_data_attributes_model
            == set_multiple_instance_policies_resources_item_policy_data_attributes_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_multiple_instance_policies_resources_item_policy_data_attributes_model_json2 = (
            set_multiple_instance_policies_resources_item_policy_data_attributes_model.to_dict()
        )
        assert (
            set_multiple_instance_policies_resources_item_policy_data_attributes_model_json2
            == set_multiple_instance_policies_resources_item_policy_data_attributes_model_json
        )


class TestModel_SetMultipleKeyPoliciesResource:
    """
    Test Class for SetMultipleKeyPoliciesResource
    """

    def test_set_multiple_key_policies_resource_serialization(self):
        """
        Test serialization/deserialization for SetMultipleKeyPoliciesResource
        """

        # Construct dict forms of any model objects needed in order to build this model.

        key_policy_dual_auth_delete_dual_auth_delete_model = {}  # KeyPolicyDualAuthDeleteDualAuthDelete
        key_policy_dual_auth_delete_dual_auth_delete_model["enabled"] = True

        key_policy_rotation_rotation_model = {}  # KeyPolicyRotationRotation
        key_policy_rotation_rotation_model["enabled"] = True
        key_policy_rotation_rotation_model["interval_month"] = 1

        # Construct a json representation of a SetMultipleKeyPoliciesResource model
        set_multiple_key_policies_resource_model_json = {}
        set_multiple_key_policies_resource_model_json["type"] = "application/vnd.ibm.kms.policy+json"
        set_multiple_key_policies_resource_model_json[
            "dualAuthDelete"
        ] = key_policy_dual_auth_delete_dual_auth_delete_model
        set_multiple_key_policies_resource_model_json["rotation"] = key_policy_rotation_rotation_model

        # Construct a model instance of SetMultipleKeyPoliciesResource by calling from_dict on the json representation
        set_multiple_key_policies_resource_model = SetMultipleKeyPoliciesResource.from_dict(
            set_multiple_key_policies_resource_model_json
        )
        assert set_multiple_key_policies_resource_model != False

        # Construct a model instance of SetMultipleKeyPoliciesResource by calling from_dict on the json representation
        set_multiple_key_policies_resource_model_dict = SetMultipleKeyPoliciesResource.from_dict(
            set_multiple_key_policies_resource_model_json
        ).__dict__
        set_multiple_key_policies_resource_model2 = SetMultipleKeyPoliciesResource(
            **set_multiple_key_policies_resource_model_dict
        )

        # Verify the model instances are equivalent
        assert set_multiple_key_policies_resource_model == set_multiple_key_policies_resource_model2

        # Convert model instance back to dict and verify no loss of data
        set_multiple_key_policies_resource_model_json2 = set_multiple_key_policies_resource_model.to_dict()
        assert set_multiple_key_policies_resource_model_json2 == set_multiple_key_policies_resource_model_json


class TestModel_UnwrapKeyResponseBody:
    """
    Test Class for UnwrapKeyResponseBody
    """

    def test_unwrap_key_response_body_serialization(self):
        """
        Test serialization/deserialization for UnwrapKeyResponseBody
        """

        # Construct a json representation of a UnwrapKeyResponseBody model
        unwrap_key_response_body_model_json = {}
        unwrap_key_response_body_model_json["plaintext"] = "testString"
        unwrap_key_response_body_model_json["ciphertext"] = "testString"

        # Construct a model instance of UnwrapKeyResponseBody by calling from_dict on the json representation
        unwrap_key_response_body_model = UnwrapKeyResponseBody.from_dict(unwrap_key_response_body_model_json)
        assert unwrap_key_response_body_model != False

        # Construct a model instance of UnwrapKeyResponseBody by calling from_dict on the json representation
        unwrap_key_response_body_model_dict = UnwrapKeyResponseBody.from_dict(
            unwrap_key_response_body_model_json
        ).__dict__
        unwrap_key_response_body_model2 = UnwrapKeyResponseBody(**unwrap_key_response_body_model_dict)

        # Verify the model instances are equivalent
        assert unwrap_key_response_body_model == unwrap_key_response_body_model2

        # Convert model instance back to dict and verify no loss of data
        unwrap_key_response_body_model_json2 = unwrap_key_response_body_model.to_dict()
        assert unwrap_key_response_body_model_json2 == unwrap_key_response_body_model_json


class TestModel_WrapKeyResponseBody:
    """
    Test Class for WrapKeyResponseBody
    """

    def test_wrap_key_response_body_serialization(self):
        """
        Test serialization/deserialization for WrapKeyResponseBody
        """

        # Construct a json representation of a WrapKeyResponseBody model
        wrap_key_response_body_model_json = {}
        wrap_key_response_body_model_json["plaintext"] = "testString"
        wrap_key_response_body_model_json["ciphertext"] = "testString"

        # Construct a model instance of WrapKeyResponseBody by calling from_dict on the json representation
        wrap_key_response_body_model = WrapKeyResponseBody.from_dict(wrap_key_response_body_model_json)
        assert wrap_key_response_body_model != False

        # Construct a model instance of WrapKeyResponseBody by calling from_dict on the json representation
        wrap_key_response_body_model_dict = WrapKeyResponseBody.from_dict(wrap_key_response_body_model_json).__dict__
        wrap_key_response_body_model2 = WrapKeyResponseBody(**wrap_key_response_body_model_dict)

        # Verify the model instances are equivalent
        assert wrap_key_response_body_model == wrap_key_response_body_model2

        # Convert model instance back to dict and verify no loss of data
        wrap_key_response_body_model_json2 = wrap_key_response_body_model.to_dict()
        assert wrap_key_response_body_model_json2 == wrap_key_response_body_model_json


class TestModel_WrappedKeyVersionKeyVersion:
    """
    Test Class for WrappedKeyVersionKeyVersion
    """

    def test_wrapped_key_version_key_version_serialization(self):
        """
        Test serialization/deserialization for WrappedKeyVersionKeyVersion
        """

        # Construct a json representation of a WrappedKeyVersionKeyVersion model
        wrapped_key_version_key_version_model_json = {}

        # Construct a model instance of WrappedKeyVersionKeyVersion by calling from_dict on the json representation
        wrapped_key_version_key_version_model = WrappedKeyVersionKeyVersion.from_dict(
            wrapped_key_version_key_version_model_json
        )
        assert wrapped_key_version_key_version_model != False

        # Construct a model instance of WrappedKeyVersionKeyVersion by calling from_dict on the json representation
        wrapped_key_version_key_version_model_dict = WrappedKeyVersionKeyVersion.from_dict(
            wrapped_key_version_key_version_model_json
        ).__dict__
        wrapped_key_version_key_version_model2 = WrappedKeyVersionKeyVersion(
            **wrapped_key_version_key_version_model_dict
        )

        # Verify the model instances are equivalent
        assert wrapped_key_version_key_version_model == wrapped_key_version_key_version_model2

        # Convert model instance back to dict and verify no loss of data
        wrapped_key_version_key_version_model_json2 = wrapped_key_version_key_version_model.to_dict()
        assert wrapped_key_version_key_version_model_json2 == wrapped_key_version_key_version_model_json


class TestModel_CollectionMetadataOneOfCollectionMetadata:
    """
    Test Class for CollectionMetadataOneOfCollectionMetadata
    """

    def test_collection_metadata_one_of_collection_metadata_serialization(self):
        """
        Test serialization/deserialization for CollectionMetadataOneOfCollectionMetadata
        """

        # Construct a json representation of a CollectionMetadataOneOfCollectionMetadata model
        collection_metadata_one_of_collection_metadata_model_json = {}
        collection_metadata_one_of_collection_metadata_model_json[
            "collectionType"
        ] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_one_of_collection_metadata_model_json["collectionTotal"] = 1

        # Construct a model instance of CollectionMetadataOneOfCollectionMetadata by calling from_dict on the json representation
        collection_metadata_one_of_collection_metadata_model = CollectionMetadataOneOfCollectionMetadata.from_dict(
            collection_metadata_one_of_collection_metadata_model_json
        )
        assert collection_metadata_one_of_collection_metadata_model != False

        # Construct a model instance of CollectionMetadataOneOfCollectionMetadata by calling from_dict on the json representation
        collection_metadata_one_of_collection_metadata_model_dict = CollectionMetadataOneOfCollectionMetadata.from_dict(
            collection_metadata_one_of_collection_metadata_model_json
        ).__dict__
        collection_metadata_one_of_collection_metadata_model2 = CollectionMetadataOneOfCollectionMetadata(
            **collection_metadata_one_of_collection_metadata_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            collection_metadata_one_of_collection_metadata_model
            == collection_metadata_one_of_collection_metadata_model2
        )

        # Convert model instance back to dict and verify no loss of data
        collection_metadata_one_of_collection_metadata_model_json2 = (
            collection_metadata_one_of_collection_metadata_model.to_dict()
        )
        assert (
            collection_metadata_one_of_collection_metadata_model_json2
            == collection_metadata_one_of_collection_metadata_model_json
        )


class TestModel_GetInstancePoliciesOneOfGetInstancePolicyAllowedIP:
    """
    Test Class for GetInstancePoliciesOneOfGetInstancePolicyAllowedIP
    """

    def test_get_instance_policies_one_of_get_instance_policy_allowed_ip_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePoliciesOneOfGetInstancePolicyAllowedIP
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_one_of_model = {}  # CollectionMetadataOneOfCollectionMetadata
        collection_metadata_one_of_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_one_of_model["collectionTotal"] = 1

        get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model = (
            {}
        )  # GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes
        get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]

        get_instance_policy_allowed_ip_resources_item_policy_data_model = (
            {}
        )  # GetInstancePolicyAllowedIPResourcesItemPolicyData
        get_instance_policy_allowed_ip_resources_item_policy_data_model["enabled"] = True
        get_instance_policy_allowed_ip_resources_item_policy_data_model[
            "attributes"
        ] = get_instance_policy_allowed_ip_resources_item_policy_data_attributes_model

        get_instance_policy_allowed_ip_resources_item_model = {}  # GetInstancePolicyAllowedIPResourcesItem
        get_instance_policy_allowed_ip_resources_item_model["policy_type"] = "testString"
        get_instance_policy_allowed_ip_resources_item_model[
            "policy_data"
        ] = get_instance_policy_allowed_ip_resources_item_policy_data_model

        # Construct a json representation of a GetInstancePoliciesOneOfGetInstancePolicyAllowedIP model
        get_instance_policies_one_of_get_instance_policy_allowed_ip_model_json = {}
        get_instance_policies_one_of_get_instance_policy_allowed_ip_model_json[
            "metadata"
        ] = collection_metadata_one_of_model
        get_instance_policies_one_of_get_instance_policy_allowed_ip_model_json["resources"] = [
            get_instance_policy_allowed_ip_resources_item_model
        ]

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyAllowedIP by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_allowed_ip_model = (
            GetInstancePoliciesOneOfGetInstancePolicyAllowedIP.from_dict(
                get_instance_policies_one_of_get_instance_policy_allowed_ip_model_json
            )
        )
        assert get_instance_policies_one_of_get_instance_policy_allowed_ip_model != False

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyAllowedIP by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_allowed_ip_model_dict = (
            GetInstancePoliciesOneOfGetInstancePolicyAllowedIP.from_dict(
                get_instance_policies_one_of_get_instance_policy_allowed_ip_model_json
            ).__dict__
        )
        get_instance_policies_one_of_get_instance_policy_allowed_ip_model2 = (
            GetInstancePoliciesOneOfGetInstancePolicyAllowedIP(
                **get_instance_policies_one_of_get_instance_policy_allowed_ip_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policies_one_of_get_instance_policy_allowed_ip_model
            == get_instance_policies_one_of_get_instance_policy_allowed_ip_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policies_one_of_get_instance_policy_allowed_ip_model_json2 = (
            get_instance_policies_one_of_get_instance_policy_allowed_ip_model.to_dict()
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_allowed_ip_model_json2
            == get_instance_policies_one_of_get_instance_policy_allowed_ip_model_json
        )


class TestModel_GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork:
    """
    Test Class for GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork
    """

    def test_get_instance_policies_one_of_get_instance_policy_allowed_network_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_one_of_model = {}  # CollectionMetadataOneOfCollectionMetadata
        collection_metadata_one_of_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_one_of_model["collectionTotal"] = 1

        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model = (
            {}
        )  # GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model[
            "allowed_network"
        ] = "public-and-private"

        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model = (
            {}
        )  # GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model[
            "enabled"
        ] = True
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model[
            "attributes"
        ] = get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_attributes_model

        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model = (
            {}
        )  # GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model[
            "policy_type"
        ] = "testString"
        get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model[
            "policy_data"
        ] = get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_policy_data_model

        # Construct a json representation of a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork model
        get_instance_policies_one_of_get_instance_policy_allowed_network_model_json = {}
        get_instance_policies_one_of_get_instance_policy_allowed_network_model_json[
            "metadata"
        ] = collection_metadata_one_of_model
        get_instance_policies_one_of_get_instance_policy_allowed_network_model_json["resources"] = [
            get_instance_policies_one_of_get_instance_policy_allowed_network_resources_item_model
        ]

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_allowed_network_model = (
            GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork.from_dict(
                get_instance_policies_one_of_get_instance_policy_allowed_network_model_json
            )
        )
        assert get_instance_policies_one_of_get_instance_policy_allowed_network_model != False

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_allowed_network_model_dict = (
            GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork.from_dict(
                get_instance_policies_one_of_get_instance_policy_allowed_network_model_json
            ).__dict__
        )
        get_instance_policies_one_of_get_instance_policy_allowed_network_model2 = (
            GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork(
                **get_instance_policies_one_of_get_instance_policy_allowed_network_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policies_one_of_get_instance_policy_allowed_network_model
            == get_instance_policies_one_of_get_instance_policy_allowed_network_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policies_one_of_get_instance_policy_allowed_network_model_json2 = (
            get_instance_policies_one_of_get_instance_policy_allowed_network_model.to_dict()
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_allowed_network_model_json2
            == get_instance_policies_one_of_get_instance_policy_allowed_network_model_json
        )


class TestModel_GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete:
    """
    Test Class for GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete
    """

    def test_get_instance_policies_one_of_get_instance_policy_dual_auth_delete_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_one_of_model = {}  # CollectionMetadataOneOfCollectionMetadata
        collection_metadata_one_of_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_one_of_model["collectionTotal"] = 1

        dual_auth_delete_properties_model = {}  # DualAuthDeleteProperties
        dual_auth_delete_properties_model["enabled"] = True

        get_instance_policy_dual_auth_delete_resources_item_model = {}  # GetInstancePolicyDualAuthDeleteResourcesItem
        get_instance_policy_dual_auth_delete_resources_item_model["policy_type"] = "testString"
        get_instance_policy_dual_auth_delete_resources_item_model["policy_data"] = dual_auth_delete_properties_model

        # Construct a json representation of a GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete model
        get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model_json = {}
        get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model_json[
            "metadata"
        ] = collection_metadata_one_of_model
        get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model_json["resources"] = [
            get_instance_policy_dual_auth_delete_resources_item_model
        ]

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model = (
            GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete.from_dict(
                get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model_json
            )
        )
        assert get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model != False

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model_dict = (
            GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete.from_dict(
                get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model_json
            ).__dict__
        )
        get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model2 = (
            GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete(
                **get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model
            == get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model_json2 = (
            get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model.to_dict()
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model_json2
            == get_instance_policies_one_of_get_instance_policy_dual_auth_delete_model_json
        )


class TestModel_GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess:
    """
    Test Class for GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess
    """

    def test_get_instance_policies_one_of_get_instance_policy_key_create_import_access_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_one_of_model = {}  # CollectionMetadataOneOfCollectionMetadata
        collection_metadata_one_of_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_one_of_model["collectionTotal"] = 1

        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model = (
            {}
        )  # GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model[
            "create_root_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model[
            "create_standard_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model[
            "import_root_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model[
            "import_standard_key"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model[
            "enforce_token"
        ] = True

        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model = (
            {}
        )  # GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model[
            "enabled"
        ] = True
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model[
            "attributes"
        ] = get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_attributes_model

        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model = (
            {}
        )  # GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model[
            "policy_type"
        ] = "testString"
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model[
            "policy_data"
        ] = get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_policy_data_model

        # Construct a json representation of a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess model
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_model_json = {}
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_model_json[
            "metadata"
        ] = collection_metadata_one_of_model
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_model_json["resources"] = [
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_resources_item_model
        ]

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_model = (
            GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess.from_dict(
                get_instance_policies_one_of_get_instance_policy_key_create_import_access_model_json
            )
        )
        assert get_instance_policies_one_of_get_instance_policy_key_create_import_access_model != False

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_model_dict = (
            GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess.from_dict(
                get_instance_policies_one_of_get_instance_policy_key_create_import_access_model_json
            ).__dict__
        )
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_model2 = (
            GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess(
                **get_instance_policies_one_of_get_instance_policy_key_create_import_access_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_model
            == get_instance_policies_one_of_get_instance_policy_key_create_import_access_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policies_one_of_get_instance_policy_key_create_import_access_model_json2 = (
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_model.to_dict()
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_key_create_import_access_model_json2
            == get_instance_policies_one_of_get_instance_policy_key_create_import_access_model_json
        )


class TestModel_GetInstancePoliciesOneOfGetInstancePolicyMetrics:
    """
    Test Class for GetInstancePoliciesOneOfGetInstancePolicyMetrics
    """

    def test_get_instance_policies_one_of_get_instance_policy_metrics_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePoliciesOneOfGetInstancePolicyMetrics
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_one_of_model = {}  # CollectionMetadataOneOfCollectionMetadata
        collection_metadata_one_of_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_one_of_model["collectionTotal"] = 1

        metrics_properties_model = {}  # MetricsProperties
        metrics_properties_model["enabled"] = True

        get_instance_policy_metrics_resources_item_model = {}  # GetInstancePolicyMetricsResourcesItem
        get_instance_policy_metrics_resources_item_model["policy_type"] = "testString"
        get_instance_policy_metrics_resources_item_model["policy_data"] = metrics_properties_model

        # Construct a json representation of a GetInstancePoliciesOneOfGetInstancePolicyMetrics model
        get_instance_policies_one_of_get_instance_policy_metrics_model_json = {}
        get_instance_policies_one_of_get_instance_policy_metrics_model_json[
            "metadata"
        ] = collection_metadata_one_of_model
        get_instance_policies_one_of_get_instance_policy_metrics_model_json["resources"] = [
            get_instance_policy_metrics_resources_item_model
        ]

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyMetrics by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_metrics_model = (
            GetInstancePoliciesOneOfGetInstancePolicyMetrics.from_dict(
                get_instance_policies_one_of_get_instance_policy_metrics_model_json
            )
        )
        assert get_instance_policies_one_of_get_instance_policy_metrics_model != False

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyMetrics by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_metrics_model_dict = (
            GetInstancePoliciesOneOfGetInstancePolicyMetrics.from_dict(
                get_instance_policies_one_of_get_instance_policy_metrics_model_json
            ).__dict__
        )
        get_instance_policies_one_of_get_instance_policy_metrics_model2 = (
            GetInstancePoliciesOneOfGetInstancePolicyMetrics(
                **get_instance_policies_one_of_get_instance_policy_metrics_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policies_one_of_get_instance_policy_metrics_model
            == get_instance_policies_one_of_get_instance_policy_metrics_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policies_one_of_get_instance_policy_metrics_model_json2 = (
            get_instance_policies_one_of_get_instance_policy_metrics_model.to_dict()
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_metrics_model_json2
            == get_instance_policies_one_of_get_instance_policy_metrics_model_json
        )


class TestModel_GetInstancePoliciesOneOfGetInstancePolicyRotation:
    """
    Test Class for GetInstancePoliciesOneOfGetInstancePolicyRotation
    """

    def test_get_instance_policies_one_of_get_instance_policy_rotation_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePoliciesOneOfGetInstancePolicyRotation
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_one_of_model = {}  # CollectionMetadataOneOfCollectionMetadata
        collection_metadata_one_of_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_one_of_model["collectionTotal"] = 1

        get_instance_policy_rotation_resources_item_policy_data_attributes_model = (
            {}
        )  # GetInstancePolicyRotationResourcesItemPolicyDataAttributes
        get_instance_policy_rotation_resources_item_policy_data_attributes_model["interval_month"] = 3

        get_instance_policy_rotation_resources_item_policy_data_model = (
            {}
        )  # GetInstancePolicyRotationResourcesItemPolicyData
        get_instance_policy_rotation_resources_item_policy_data_model["enabled"] = True
        get_instance_policy_rotation_resources_item_policy_data_model[
            "attributes"
        ] = get_instance_policy_rotation_resources_item_policy_data_attributes_model

        get_instance_policy_rotation_resources_item_model = {}  # GetInstancePolicyRotationResourcesItem
        get_instance_policy_rotation_resources_item_model["policy_type"] = "testString"
        get_instance_policy_rotation_resources_item_model[
            "policy_data"
        ] = get_instance_policy_rotation_resources_item_policy_data_model

        # Construct a json representation of a GetInstancePoliciesOneOfGetInstancePolicyRotation model
        get_instance_policies_one_of_get_instance_policy_rotation_model_json = {}
        get_instance_policies_one_of_get_instance_policy_rotation_model_json[
            "metadata"
        ] = collection_metadata_one_of_model
        get_instance_policies_one_of_get_instance_policy_rotation_model_json["resources"] = [
            get_instance_policy_rotation_resources_item_model
        ]

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyRotation by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_rotation_model = (
            GetInstancePoliciesOneOfGetInstancePolicyRotation.from_dict(
                get_instance_policies_one_of_get_instance_policy_rotation_model_json
            )
        )
        assert get_instance_policies_one_of_get_instance_policy_rotation_model != False

        # Construct a model instance of GetInstancePoliciesOneOfGetInstancePolicyRotation by calling from_dict on the json representation
        get_instance_policies_one_of_get_instance_policy_rotation_model_dict = (
            GetInstancePoliciesOneOfGetInstancePolicyRotation.from_dict(
                get_instance_policies_one_of_get_instance_policy_rotation_model_json
            ).__dict__
        )
        get_instance_policies_one_of_get_instance_policy_rotation_model2 = (
            GetInstancePoliciesOneOfGetInstancePolicyRotation(
                **get_instance_policies_one_of_get_instance_policy_rotation_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policies_one_of_get_instance_policy_rotation_model
            == get_instance_policies_one_of_get_instance_policy_rotation_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policies_one_of_get_instance_policy_rotation_model_json2 = (
            get_instance_policies_one_of_get_instance_policy_rotation_model.to_dict()
        )
        assert (
            get_instance_policies_one_of_get_instance_policy_rotation_model_json2
            == get_instance_policies_one_of_get_instance_policy_rotation_model_json
        )


class TestModel_GetInstancePoliciesOneOfGetMultipleInstancePolicies:
    """
    Test Class for GetInstancePoliciesOneOfGetMultipleInstancePolicies
    """

    def test_get_instance_policies_one_of_get_multiple_instance_policies_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetInstancePoliciesOneOfGetMultipleInstancePolicies
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_one_of_model = {}  # CollectionMetadataOneOfCollectionMetadata
        collection_metadata_one_of_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_one_of_model["collectionTotal"] = 1

        instance_policy_properties_attributes_model = {}  # InstancePolicyPropertiesAttributes
        instance_policy_properties_attributes_model["allowed_network"] = "public-and-private"
        instance_policy_properties_attributes_model["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]
        instance_policy_properties_attributes_model["create_root_key"] = True
        instance_policy_properties_attributes_model["create_standard_key"] = True
        instance_policy_properties_attributes_model["import_root_key"] = True
        instance_policy_properties_attributes_model["import_standard_key"] = True
        instance_policy_properties_attributes_model["enforce_token"] = True
        instance_policy_properties_attributes_model["interval_month"] = 3

        instance_policy_properties_model = {}  # InstancePolicyProperties
        instance_policy_properties_model["enabled"] = True
        instance_policy_properties_model["attributes"] = instance_policy_properties_attributes_model

        instance_policy_resource_model = {}  # InstancePolicyResource
        instance_policy_resource_model["policy_type"] = "testString"
        instance_policy_resource_model["policy_data"] = instance_policy_properties_model

        # Construct a json representation of a GetInstancePoliciesOneOfGetMultipleInstancePolicies model
        get_instance_policies_one_of_get_multiple_instance_policies_model_json = {}
        get_instance_policies_one_of_get_multiple_instance_policies_model_json[
            "metadata"
        ] = collection_metadata_one_of_model
        get_instance_policies_one_of_get_multiple_instance_policies_model_json["resources"] = [
            instance_policy_resource_model
        ]

        # Construct a model instance of GetInstancePoliciesOneOfGetMultipleInstancePolicies by calling from_dict on the json representation
        get_instance_policies_one_of_get_multiple_instance_policies_model = (
            GetInstancePoliciesOneOfGetMultipleInstancePolicies.from_dict(
                get_instance_policies_one_of_get_multiple_instance_policies_model_json
            )
        )
        assert get_instance_policies_one_of_get_multiple_instance_policies_model != False

        # Construct a model instance of GetInstancePoliciesOneOfGetMultipleInstancePolicies by calling from_dict on the json representation
        get_instance_policies_one_of_get_multiple_instance_policies_model_dict = (
            GetInstancePoliciesOneOfGetMultipleInstancePolicies.from_dict(
                get_instance_policies_one_of_get_multiple_instance_policies_model_json
            ).__dict__
        )
        get_instance_policies_one_of_get_multiple_instance_policies_model2 = (
            GetInstancePoliciesOneOfGetMultipleInstancePolicies(
                **get_instance_policies_one_of_get_multiple_instance_policies_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            get_instance_policies_one_of_get_multiple_instance_policies_model
            == get_instance_policies_one_of_get_multiple_instance_policies_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_instance_policies_one_of_get_multiple_instance_policies_model_json2 = (
            get_instance_policies_one_of_get_multiple_instance_policies_model.to_dict()
        )
        assert (
            get_instance_policies_one_of_get_multiple_instance_policies_model_json2
            == get_instance_policies_one_of_get_multiple_instance_policies_model_json
        )


class TestModel_GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete:
    """
    Test Class for GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete
    """

    def test_get_key_policies_one_of_get_key_policy_dual_auth_delete_serialization(
        self,
    ):
        """
        Test serialization/deserialization for GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        key_policy_dual_auth_delete_dual_auth_delete_model = {}  # KeyPolicyDualAuthDeleteDualAuthDelete
        key_policy_dual_auth_delete_dual_auth_delete_model["enabled"] = True

        get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model = (
            {}
        )  # GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem
        get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model[
            "type"
        ] = "application/vnd.ibm.kms.policy+json"
        get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model[
            "dualAuthDelete"
        ] = key_policy_dual_auth_delete_dual_auth_delete_model

        # Construct a json representation of a GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete model
        get_key_policies_one_of_get_key_policy_dual_auth_delete_model_json = {}
        get_key_policies_one_of_get_key_policy_dual_auth_delete_model_json["metadata"] = collection_metadata_model
        get_key_policies_one_of_get_key_policy_dual_auth_delete_model_json["resources"] = [
            get_key_policies_one_of_get_key_policy_dual_auth_delete_resources_item_model
        ]

        # Construct a model instance of GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete by calling from_dict on the json representation
        get_key_policies_one_of_get_key_policy_dual_auth_delete_model = (
            GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete.from_dict(
                get_key_policies_one_of_get_key_policy_dual_auth_delete_model_json
            )
        )
        assert get_key_policies_one_of_get_key_policy_dual_auth_delete_model != False

        # Construct a model instance of GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete by calling from_dict on the json representation
        get_key_policies_one_of_get_key_policy_dual_auth_delete_model_dict = (
            GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete.from_dict(
                get_key_policies_one_of_get_key_policy_dual_auth_delete_model_json
            ).__dict__
        )
        get_key_policies_one_of_get_key_policy_dual_auth_delete_model2 = GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete(
            **get_key_policies_one_of_get_key_policy_dual_auth_delete_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            get_key_policies_one_of_get_key_policy_dual_auth_delete_model
            == get_key_policies_one_of_get_key_policy_dual_auth_delete_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_key_policies_one_of_get_key_policy_dual_auth_delete_model_json2 = (
            get_key_policies_one_of_get_key_policy_dual_auth_delete_model.to_dict()
        )
        assert (
            get_key_policies_one_of_get_key_policy_dual_auth_delete_model_json2
            == get_key_policies_one_of_get_key_policy_dual_auth_delete_model_json
        )


class TestModel_GetKeyPoliciesOneOfGetKeyPolicyRotation:
    """
    Test Class for GetKeyPoliciesOneOfGetKeyPolicyRotation
    """

    def test_get_key_policies_one_of_get_key_policy_rotation_serialization(self):
        """
        Test serialization/deserialization for GetKeyPoliciesOneOfGetKeyPolicyRotation
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        key_policy_rotation_rotation_model = {}  # KeyPolicyRotationRotation
        key_policy_rotation_rotation_model["enabled"] = True
        key_policy_rotation_rotation_model["interval_month"] = 1

        get_key_policy_rotation_resources_item_model = {}  # GetKeyPolicyRotationResourcesItem
        get_key_policy_rotation_resources_item_model["type"] = "application/vnd.ibm.kms.policy+json"
        get_key_policy_rotation_resources_item_model["rotation"] = key_policy_rotation_rotation_model

        # Construct a json representation of a GetKeyPoliciesOneOfGetKeyPolicyRotation model
        get_key_policies_one_of_get_key_policy_rotation_model_json = {}
        get_key_policies_one_of_get_key_policy_rotation_model_json["metadata"] = collection_metadata_model
        get_key_policies_one_of_get_key_policy_rotation_model_json["resources"] = [
            get_key_policy_rotation_resources_item_model
        ]

        # Construct a model instance of GetKeyPoliciesOneOfGetKeyPolicyRotation by calling from_dict on the json representation
        get_key_policies_one_of_get_key_policy_rotation_model = GetKeyPoliciesOneOfGetKeyPolicyRotation.from_dict(
            get_key_policies_one_of_get_key_policy_rotation_model_json
        )
        assert get_key_policies_one_of_get_key_policy_rotation_model != False

        # Construct a model instance of GetKeyPoliciesOneOfGetKeyPolicyRotation by calling from_dict on the json representation
        get_key_policies_one_of_get_key_policy_rotation_model_dict = GetKeyPoliciesOneOfGetKeyPolicyRotation.from_dict(
            get_key_policies_one_of_get_key_policy_rotation_model_json
        ).__dict__
        get_key_policies_one_of_get_key_policy_rotation_model2 = GetKeyPoliciesOneOfGetKeyPolicyRotation(
            **get_key_policies_one_of_get_key_policy_rotation_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            get_key_policies_one_of_get_key_policy_rotation_model
            == get_key_policies_one_of_get_key_policy_rotation_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_key_policies_one_of_get_key_policy_rotation_model_json2 = (
            get_key_policies_one_of_get_key_policy_rotation_model.to_dict()
        )
        assert (
            get_key_policies_one_of_get_key_policy_rotation_model_json2
            == get_key_policies_one_of_get_key_policy_rotation_model_json
        )


class TestModel_GetKeyPoliciesOneOfGetMultipleKeyPolicies:
    """
    Test Class for GetKeyPoliciesOneOfGetMultipleKeyPolicies
    """

    def test_get_key_policies_one_of_get_multiple_key_policies_serialization(self):
        """
        Test serialization/deserialization for GetKeyPoliciesOneOfGetMultipleKeyPolicies
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        get_multiple_key_policies_resource_dual_auth_delete_model = {}  # GetMultipleKeyPoliciesResourceDualAuthDelete
        get_multiple_key_policies_resource_dual_auth_delete_model["enabled"] = True

        key_policy_rotation_non_required_rotation_model = {}  # KeyPolicyRotationNonRequiredRotation
        key_policy_rotation_non_required_rotation_model["enabled"] = True
        key_policy_rotation_non_required_rotation_model["interval_month"] = 1

        get_multiple_key_policies_resource_model = {}  # GetMultipleKeyPoliciesResource
        get_multiple_key_policies_resource_model[
            "dualAuthDelete"
        ] = get_multiple_key_policies_resource_dual_auth_delete_model
        get_multiple_key_policies_resource_model["rotation"] = key_policy_rotation_non_required_rotation_model

        # Construct a json representation of a GetKeyPoliciesOneOfGetMultipleKeyPolicies model
        get_key_policies_one_of_get_multiple_key_policies_model_json = {}
        get_key_policies_one_of_get_multiple_key_policies_model_json["metadata"] = collection_metadata_model
        get_key_policies_one_of_get_multiple_key_policies_model_json["resources"] = [
            get_multiple_key_policies_resource_model
        ]

        # Construct a model instance of GetKeyPoliciesOneOfGetMultipleKeyPolicies by calling from_dict on the json representation
        get_key_policies_one_of_get_multiple_key_policies_model = GetKeyPoliciesOneOfGetMultipleKeyPolicies.from_dict(
            get_key_policies_one_of_get_multiple_key_policies_model_json
        )
        assert get_key_policies_one_of_get_multiple_key_policies_model != False

        # Construct a model instance of GetKeyPoliciesOneOfGetMultipleKeyPolicies by calling from_dict on the json representation
        get_key_policies_one_of_get_multiple_key_policies_model_dict = (
            GetKeyPoliciesOneOfGetMultipleKeyPolicies.from_dict(
                get_key_policies_one_of_get_multiple_key_policies_model_json
            ).__dict__
        )
        get_key_policies_one_of_get_multiple_key_policies_model2 = GetKeyPoliciesOneOfGetMultipleKeyPolicies(
            **get_key_policies_one_of_get_multiple_key_policies_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            get_key_policies_one_of_get_multiple_key_policies_model
            == get_key_policies_one_of_get_multiple_key_policies_model2
        )

        # Convert model instance back to dict and verify no loss of data
        get_key_policies_one_of_get_multiple_key_policies_model_json2 = (
            get_key_policies_one_of_get_multiple_key_policies_model.to_dict()
        )
        assert (
            get_key_policies_one_of_get_multiple_key_policies_model_json2
            == get_key_policies_one_of_get_multiple_key_policies_model_json
        )


class TestModel_KMIPProfileDataBodyKMIPProfileDataNative:
    """
    Test Class for KMIPProfileDataBodyKMIPProfileDataNative
    """

    def test_kmip_profile_data_body_kmip_profile_data_native_serialization(self):
        """
        Test serialization/deserialization for KMIPProfileDataBodyKMIPProfileDataNative
        """

        # Construct a json representation of a KMIPProfileDataBodyKMIPProfileDataNative model
        kmip_profile_data_body_kmip_profile_data_native_model_json = {}
        kmip_profile_data_body_kmip_profile_data_native_model_json["crk_id"] = "feddecaf-0000-0000-0000-1234567890ab"

        # Construct a model instance of KMIPProfileDataBodyKMIPProfileDataNative by calling from_dict on the json representation
        kmip_profile_data_body_kmip_profile_data_native_model = KMIPProfileDataBodyKMIPProfileDataNative.from_dict(
            kmip_profile_data_body_kmip_profile_data_native_model_json
        )
        assert kmip_profile_data_body_kmip_profile_data_native_model != False

        # Construct a model instance of KMIPProfileDataBodyKMIPProfileDataNative by calling from_dict on the json representation
        kmip_profile_data_body_kmip_profile_data_native_model_dict = KMIPProfileDataBodyKMIPProfileDataNative.from_dict(
            kmip_profile_data_body_kmip_profile_data_native_model_json
        ).__dict__
        kmip_profile_data_body_kmip_profile_data_native_model2 = KMIPProfileDataBodyKMIPProfileDataNative(
            **kmip_profile_data_body_kmip_profile_data_native_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            kmip_profile_data_body_kmip_profile_data_native_model
            == kmip_profile_data_body_kmip_profile_data_native_model2
        )

        # Convert model instance back to dict and verify no loss of data
        kmip_profile_data_body_kmip_profile_data_native_model_json2 = (
            kmip_profile_data_body_kmip_profile_data_native_model.to_dict()
        )
        assert (
            kmip_profile_data_body_kmip_profile_data_native_model_json2
            == kmip_profile_data_body_kmip_profile_data_native_model_json
        )


class TestModel_KeyActionOneOfResponseRewrapKeyResponseBody:
    """
    Test Class for KeyActionOneOfResponseRewrapKeyResponseBody
    """

    def test_key_action_one_of_response_rewrap_key_response_body_serialization(self):
        """
        Test serialization/deserialization for KeyActionOneOfResponseRewrapKeyResponseBody
        """

        # Construct a json representation of a KeyActionOneOfResponseRewrapKeyResponseBody model
        key_action_one_of_response_rewrap_key_response_body_model_json = {}
        key_action_one_of_response_rewrap_key_response_body_model_json["ciphertext"] = "testString"

        # Construct a model instance of KeyActionOneOfResponseRewrapKeyResponseBody by calling from_dict on the json representation
        key_action_one_of_response_rewrap_key_response_body_model = (
            KeyActionOneOfResponseRewrapKeyResponseBody.from_dict(
                key_action_one_of_response_rewrap_key_response_body_model_json
            )
        )
        assert key_action_one_of_response_rewrap_key_response_body_model != False

        # Construct a model instance of KeyActionOneOfResponseRewrapKeyResponseBody by calling from_dict on the json representation
        key_action_one_of_response_rewrap_key_response_body_model_dict = (
            KeyActionOneOfResponseRewrapKeyResponseBody.from_dict(
                key_action_one_of_response_rewrap_key_response_body_model_json
            ).__dict__
        )
        key_action_one_of_response_rewrap_key_response_body_model2 = KeyActionOneOfResponseRewrapKeyResponseBody(
            **key_action_one_of_response_rewrap_key_response_body_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            key_action_one_of_response_rewrap_key_response_body_model
            == key_action_one_of_response_rewrap_key_response_body_model2
        )

        # Convert model instance back to dict and verify no loss of data
        key_action_one_of_response_rewrap_key_response_body_model_json2 = (
            key_action_one_of_response_rewrap_key_response_body_model.to_dict()
        )
        assert (
            key_action_one_of_response_rewrap_key_response_body_model_json2
            == key_action_one_of_response_rewrap_key_response_body_model_json
        )


class TestModel_KeyActionOneOfResponseUnwrapKeyResponseBody:
    """
    Test Class for KeyActionOneOfResponseUnwrapKeyResponseBody
    """

    def test_key_action_one_of_response_unwrap_key_response_body_serialization(self):
        """
        Test serialization/deserialization for KeyActionOneOfResponseUnwrapKeyResponseBody
        """

        # Construct a json representation of a KeyActionOneOfResponseUnwrapKeyResponseBody model
        key_action_one_of_response_unwrap_key_response_body_model_json = {}
        key_action_one_of_response_unwrap_key_response_body_model_json["plaintext"] = "testString"
        key_action_one_of_response_unwrap_key_response_body_model_json["ciphertext"] = "testString"

        # Construct a model instance of KeyActionOneOfResponseUnwrapKeyResponseBody by calling from_dict on the json representation
        key_action_one_of_response_unwrap_key_response_body_model = (
            KeyActionOneOfResponseUnwrapKeyResponseBody.from_dict(
                key_action_one_of_response_unwrap_key_response_body_model_json
            )
        )
        assert key_action_one_of_response_unwrap_key_response_body_model != False

        # Construct a model instance of KeyActionOneOfResponseUnwrapKeyResponseBody by calling from_dict on the json representation
        key_action_one_of_response_unwrap_key_response_body_model_dict = (
            KeyActionOneOfResponseUnwrapKeyResponseBody.from_dict(
                key_action_one_of_response_unwrap_key_response_body_model_json
            ).__dict__
        )
        key_action_one_of_response_unwrap_key_response_body_model2 = KeyActionOneOfResponseUnwrapKeyResponseBody(
            **key_action_one_of_response_unwrap_key_response_body_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            key_action_one_of_response_unwrap_key_response_body_model
            == key_action_one_of_response_unwrap_key_response_body_model2
        )

        # Convert model instance back to dict and verify no loss of data
        key_action_one_of_response_unwrap_key_response_body_model_json2 = (
            key_action_one_of_response_unwrap_key_response_body_model.to_dict()
        )
        assert (
            key_action_one_of_response_unwrap_key_response_body_model_json2
            == key_action_one_of_response_unwrap_key_response_body_model_json
        )


class TestModel_KeyActionOneOfResponseWrapKeyResponseBody:
    """
    Test Class for KeyActionOneOfResponseWrapKeyResponseBody
    """

    def test_key_action_one_of_response_wrap_key_response_body_serialization(self):
        """
        Test serialization/deserialization for KeyActionOneOfResponseWrapKeyResponseBody
        """

        # Construct a json representation of a KeyActionOneOfResponseWrapKeyResponseBody model
        key_action_one_of_response_wrap_key_response_body_model_json = {}
        key_action_one_of_response_wrap_key_response_body_model_json["plaintext"] = "testString"
        key_action_one_of_response_wrap_key_response_body_model_json["ciphertext"] = "testString"

        # Construct a model instance of KeyActionOneOfResponseWrapKeyResponseBody by calling from_dict on the json representation
        key_action_one_of_response_wrap_key_response_body_model = KeyActionOneOfResponseWrapKeyResponseBody.from_dict(
            key_action_one_of_response_wrap_key_response_body_model_json
        )
        assert key_action_one_of_response_wrap_key_response_body_model != False

        # Construct a model instance of KeyActionOneOfResponseWrapKeyResponseBody by calling from_dict on the json representation
        key_action_one_of_response_wrap_key_response_body_model_dict = (
            KeyActionOneOfResponseWrapKeyResponseBody.from_dict(
                key_action_one_of_response_wrap_key_response_body_model_json
            ).__dict__
        )
        key_action_one_of_response_wrap_key_response_body_model2 = KeyActionOneOfResponseWrapKeyResponseBody(
            **key_action_one_of_response_wrap_key_response_body_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            key_action_one_of_response_wrap_key_response_body_model
            == key_action_one_of_response_wrap_key_response_body_model2
        )

        # Convert model instance back to dict and verify no loss of data
        key_action_one_of_response_wrap_key_response_body_model_json2 = (
            key_action_one_of_response_wrap_key_response_body_model.to_dict()
        )
        assert (
            key_action_one_of_response_wrap_key_response_body_model_json2
            == key_action_one_of_response_wrap_key_response_body_model_json
        )


class TestModel_ListCollectionMetadataCollectionMetadata:
    """
    Test Class for ListCollectionMetadataCollectionMetadata
    """

    def test_list_collection_metadata_collection_metadata_serialization(self):
        """
        Test serialization/deserialization for ListCollectionMetadataCollectionMetadata
        """

        # Construct a json representation of a ListCollectionMetadataCollectionMetadata model
        list_collection_metadata_collection_metadata_model_json = {}
        list_collection_metadata_collection_metadata_model_json[
            "collectionType"
        ] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        list_collection_metadata_collection_metadata_model_json["collectionTotal"] = 1

        # Construct a model instance of ListCollectionMetadataCollectionMetadata by calling from_dict on the json representation
        list_collection_metadata_collection_metadata_model = ListCollectionMetadataCollectionMetadata.from_dict(
            list_collection_metadata_collection_metadata_model_json
        )
        assert list_collection_metadata_collection_metadata_model != False

        # Construct a model instance of ListCollectionMetadataCollectionMetadata by calling from_dict on the json representation
        list_collection_metadata_collection_metadata_model_dict = ListCollectionMetadataCollectionMetadata.from_dict(
            list_collection_metadata_collection_metadata_model_json
        ).__dict__
        list_collection_metadata_collection_metadata_model2 = ListCollectionMetadataCollectionMetadata(
            **list_collection_metadata_collection_metadata_model_dict
        )

        # Verify the model instances are equivalent
        assert list_collection_metadata_collection_metadata_model == list_collection_metadata_collection_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        list_collection_metadata_collection_metadata_model_json2 = (
            list_collection_metadata_collection_metadata_model.to_dict()
        )
        assert (
            list_collection_metadata_collection_metadata_model_json2
            == list_collection_metadata_collection_metadata_model_json
        )


class TestModel_ListCollectionMetadataCollectionMetadataWithTotalCount:
    """
    Test Class for ListCollectionMetadataCollectionMetadataWithTotalCount
    """

    def test_list_collection_metadata_collection_metadata_with_total_count_serialization(
        self,
    ):
        """
        Test serialization/deserialization for ListCollectionMetadataCollectionMetadataWithTotalCount
        """

        # Construct a json representation of a ListCollectionMetadataCollectionMetadataWithTotalCount model
        list_collection_metadata_collection_metadata_with_total_count_model_json = {}
        list_collection_metadata_collection_metadata_with_total_count_model_json[
            "collectionType"
        ] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        list_collection_metadata_collection_metadata_with_total_count_model_json["collectionTotal"] = 1
        list_collection_metadata_collection_metadata_with_total_count_model_json["totalCount"] = 1

        # Construct a model instance of ListCollectionMetadataCollectionMetadataWithTotalCount by calling from_dict on the json representation
        list_collection_metadata_collection_metadata_with_total_count_model = (
            ListCollectionMetadataCollectionMetadataWithTotalCount.from_dict(
                list_collection_metadata_collection_metadata_with_total_count_model_json
            )
        )
        assert list_collection_metadata_collection_metadata_with_total_count_model != False

        # Construct a model instance of ListCollectionMetadataCollectionMetadataWithTotalCount by calling from_dict on the json representation
        list_collection_metadata_collection_metadata_with_total_count_model_dict = (
            ListCollectionMetadataCollectionMetadataWithTotalCount.from_dict(
                list_collection_metadata_collection_metadata_with_total_count_model_json
            ).__dict__
        )
        list_collection_metadata_collection_metadata_with_total_count_model2 = (
            ListCollectionMetadataCollectionMetadataWithTotalCount(
                **list_collection_metadata_collection_metadata_with_total_count_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            list_collection_metadata_collection_metadata_with_total_count_model
            == list_collection_metadata_collection_metadata_with_total_count_model2
        )

        # Convert model instance back to dict and verify no loss of data
        list_collection_metadata_collection_metadata_with_total_count_model_json2 = (
            list_collection_metadata_collection_metadata_with_total_count_model.to_dict()
        )
        assert (
            list_collection_metadata_collection_metadata_with_total_count_model_json2
            == list_collection_metadata_collection_metadata_with_total_count_model_json
        )


class TestModel_SetInstancePoliciesOneOfSetInstancePolicyAllowedIP:
    """
    Test Class for SetInstancePoliciesOneOfSetInstancePolicyAllowedIP
    """

    def test_set_instance_policies_one_of_set_instance_policy_allowed_ip_serialization(
        self,
    ):
        """
        Test serialization/deserialization for SetInstancePoliciesOneOfSetInstancePolicyAllowedIP
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        instance_policy_allowed_ip_policy_data_attributes_model = {}  # InstancePolicyAllowedIPPolicyDataAttributes
        instance_policy_allowed_ip_policy_data_attributes_model["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]

        instance_policy_allowed_ip_policy_data_model = {}  # InstancePolicyAllowedIPPolicyData
        instance_policy_allowed_ip_policy_data_model["enabled"] = True
        instance_policy_allowed_ip_policy_data_model[
            "attributes"
        ] = instance_policy_allowed_ip_policy_data_attributes_model

        set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model = (
            {}
        )  # SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem
        set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model["policy_type"] = "allowedIP"
        set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model[
            "policy_data"
        ] = instance_policy_allowed_ip_policy_data_model

        # Construct a json representation of a SetInstancePoliciesOneOfSetInstancePolicyAllowedIP model
        set_instance_policies_one_of_set_instance_policy_allowed_ip_model_json = {}
        set_instance_policies_one_of_set_instance_policy_allowed_ip_model_json["metadata"] = collection_metadata_model
        set_instance_policies_one_of_set_instance_policy_allowed_ip_model_json["resources"] = [
            set_instance_policies_one_of_set_instance_policy_allowed_ip_resources_item_model
        ]

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyAllowedIP by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_allowed_ip_model = (
            SetInstancePoliciesOneOfSetInstancePolicyAllowedIP.from_dict(
                set_instance_policies_one_of_set_instance_policy_allowed_ip_model_json
            )
        )
        assert set_instance_policies_one_of_set_instance_policy_allowed_ip_model != False

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyAllowedIP by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_allowed_ip_model_dict = (
            SetInstancePoliciesOneOfSetInstancePolicyAllowedIP.from_dict(
                set_instance_policies_one_of_set_instance_policy_allowed_ip_model_json
            ).__dict__
        )
        set_instance_policies_one_of_set_instance_policy_allowed_ip_model2 = (
            SetInstancePoliciesOneOfSetInstancePolicyAllowedIP(
                **set_instance_policies_one_of_set_instance_policy_allowed_ip_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            set_instance_policies_one_of_set_instance_policy_allowed_ip_model
            == set_instance_policies_one_of_set_instance_policy_allowed_ip_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_instance_policies_one_of_set_instance_policy_allowed_ip_model_json2 = (
            set_instance_policies_one_of_set_instance_policy_allowed_ip_model.to_dict()
        )
        assert (
            set_instance_policies_one_of_set_instance_policy_allowed_ip_model_json2
            == set_instance_policies_one_of_set_instance_policy_allowed_ip_model_json
        )


class TestModel_SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork:
    """
    Test Class for SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork
    """

    def test_set_instance_policies_one_of_set_instance_policy_allowed_network_serialization(
        self,
    ):
        """
        Test serialization/deserialization for SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        instance_policy_allowed_network_policy_data_attributes_model = (
            {}
        )  # InstancePolicyAllowedNetworkPolicyDataAttributes
        instance_policy_allowed_network_policy_data_attributes_model["allowed_network"] = "public-and-private"

        instance_policy_allowed_network_policy_data_model = {}  # InstancePolicyAllowedNetworkPolicyData
        instance_policy_allowed_network_policy_data_model["enabled"] = True
        instance_policy_allowed_network_policy_data_model[
            "attributes"
        ] = instance_policy_allowed_network_policy_data_attributes_model

        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model = (
            {}
        )  # SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model[
            "policy_type"
        ] = "allowedNetwork"
        set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model[
            "policy_data"
        ] = instance_policy_allowed_network_policy_data_model

        # Construct a json representation of a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork model
        set_instance_policies_one_of_set_instance_policy_allowed_network_model_json = {}
        set_instance_policies_one_of_set_instance_policy_allowed_network_model_json[
            "metadata"
        ] = collection_metadata_model
        set_instance_policies_one_of_set_instance_policy_allowed_network_model_json["resources"] = [
            set_instance_policies_one_of_set_instance_policy_allowed_network_resources_item_model
        ]

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_allowed_network_model = (
            SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork.from_dict(
                set_instance_policies_one_of_set_instance_policy_allowed_network_model_json
            )
        )
        assert set_instance_policies_one_of_set_instance_policy_allowed_network_model != False

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_allowed_network_model_dict = (
            SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork.from_dict(
                set_instance_policies_one_of_set_instance_policy_allowed_network_model_json
            ).__dict__
        )
        set_instance_policies_one_of_set_instance_policy_allowed_network_model2 = (
            SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork(
                **set_instance_policies_one_of_set_instance_policy_allowed_network_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            set_instance_policies_one_of_set_instance_policy_allowed_network_model
            == set_instance_policies_one_of_set_instance_policy_allowed_network_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_instance_policies_one_of_set_instance_policy_allowed_network_model_json2 = (
            set_instance_policies_one_of_set_instance_policy_allowed_network_model.to_dict()
        )
        assert (
            set_instance_policies_one_of_set_instance_policy_allowed_network_model_json2
            == set_instance_policies_one_of_set_instance_policy_allowed_network_model_json
        )


class TestModel_SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete:
    """
    Test Class for SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete
    """

    def test_set_instance_policies_one_of_set_instance_policy_dual_auth_delete_serialization(
        self,
    ):
        """
        Test serialization/deserialization for SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        dual_auth_delete_properties_model = {}  # DualAuthDeleteProperties
        dual_auth_delete_properties_model["enabled"] = True

        set_instance_policy_dual_auth_delete_resources_item_model = {}  # SetInstancePolicyDualAuthDeleteResourcesItem
        set_instance_policy_dual_auth_delete_resources_item_model["policy_type"] = "dualAuthDelete"
        set_instance_policy_dual_auth_delete_resources_item_model["policy_data"] = dual_auth_delete_properties_model

        # Construct a json representation of a SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete model
        set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model_json = {}
        set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model_json[
            "metadata"
        ] = collection_metadata_model
        set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model_json["resources"] = [
            set_instance_policy_dual_auth_delete_resources_item_model
        ]

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model = (
            SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete.from_dict(
                set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model_json
            )
        )
        assert set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model != False

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model_dict = (
            SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete.from_dict(
                set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model_json
            ).__dict__
        )
        set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model2 = (
            SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete(
                **set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model
            == set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model_json2 = (
            set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model.to_dict()
        )
        assert (
            set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model_json2
            == set_instance_policies_one_of_set_instance_policy_dual_auth_delete_model_json
        )


class TestModel_SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess:
    """
    Test Class for SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess
    """

    def test_set_instance_policies_one_of_set_instance_policy_key_create_import_access_serialization(
        self,
    ):
        """
        Test serialization/deserialization for SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        instance_policy_key_create_import_access_policy_data_attributes_model = (
            {}
        )  # InstancePolicyKeyCreateImportAccessPolicyDataAttributes
        instance_policy_key_create_import_access_policy_data_attributes_model["create_root_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model["create_standard_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model["import_root_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model["import_standard_key"] = True
        instance_policy_key_create_import_access_policy_data_attributes_model["enforce_token"] = True

        instance_policy_key_create_import_access_policy_data_model = {}  # InstancePolicyKeyCreateImportAccessPolicyData
        instance_policy_key_create_import_access_policy_data_model["enabled"] = True
        instance_policy_key_create_import_access_policy_data_model[
            "attributes"
        ] = instance_policy_key_create_import_access_policy_data_attributes_model

        set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model = (
            {}
        )  # SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model[
            "policy_type"
        ] = "keyCreateImportAccess"
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model[
            "policy_data"
        ] = instance_policy_key_create_import_access_policy_data_model

        # Construct a json representation of a SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess model
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_model_json = {}
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_model_json[
            "metadata"
        ] = collection_metadata_model
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_model_json["resources"] = [
            set_instance_policies_one_of_set_instance_policy_key_create_import_access_resources_item_model
        ]

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_model = (
            SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess.from_dict(
                set_instance_policies_one_of_set_instance_policy_key_create_import_access_model_json
            )
        )
        assert set_instance_policies_one_of_set_instance_policy_key_create_import_access_model != False

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_model_dict = (
            SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess.from_dict(
                set_instance_policies_one_of_set_instance_policy_key_create_import_access_model_json
            ).__dict__
        )
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_model2 = (
            SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess(
                **set_instance_policies_one_of_set_instance_policy_key_create_import_access_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            set_instance_policies_one_of_set_instance_policy_key_create_import_access_model
            == set_instance_policies_one_of_set_instance_policy_key_create_import_access_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_instance_policies_one_of_set_instance_policy_key_create_import_access_model_json2 = (
            set_instance_policies_one_of_set_instance_policy_key_create_import_access_model.to_dict()
        )
        assert (
            set_instance_policies_one_of_set_instance_policy_key_create_import_access_model_json2
            == set_instance_policies_one_of_set_instance_policy_key_create_import_access_model_json
        )


class TestModel_SetInstancePoliciesOneOfSetInstancePolicyMetrics:
    """
    Test Class for SetInstancePoliciesOneOfSetInstancePolicyMetrics
    """

    def test_set_instance_policies_one_of_set_instance_policy_metrics_serialization(
        self,
    ):
        """
        Test serialization/deserialization for SetInstancePoliciesOneOfSetInstancePolicyMetrics
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        metrics_properties_model = {}  # MetricsProperties
        metrics_properties_model["enabled"] = True

        set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model = (
            {}
        )  # SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem
        set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model["policy_type"] = "metrics"
        set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model[
            "policy_data"
        ] = metrics_properties_model

        # Construct a json representation of a SetInstancePoliciesOneOfSetInstancePolicyMetrics model
        set_instance_policies_one_of_set_instance_policy_metrics_model_json = {}
        set_instance_policies_one_of_set_instance_policy_metrics_model_json["metadata"] = collection_metadata_model
        set_instance_policies_one_of_set_instance_policy_metrics_model_json["resources"] = [
            set_instance_policies_one_of_set_instance_policy_metrics_resources_item_model
        ]

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyMetrics by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_metrics_model = (
            SetInstancePoliciesOneOfSetInstancePolicyMetrics.from_dict(
                set_instance_policies_one_of_set_instance_policy_metrics_model_json
            )
        )
        assert set_instance_policies_one_of_set_instance_policy_metrics_model != False

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyMetrics by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_metrics_model_dict = (
            SetInstancePoliciesOneOfSetInstancePolicyMetrics.from_dict(
                set_instance_policies_one_of_set_instance_policy_metrics_model_json
            ).__dict__
        )
        set_instance_policies_one_of_set_instance_policy_metrics_model2 = (
            SetInstancePoliciesOneOfSetInstancePolicyMetrics(
                **set_instance_policies_one_of_set_instance_policy_metrics_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            set_instance_policies_one_of_set_instance_policy_metrics_model
            == set_instance_policies_one_of_set_instance_policy_metrics_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_instance_policies_one_of_set_instance_policy_metrics_model_json2 = (
            set_instance_policies_one_of_set_instance_policy_metrics_model.to_dict()
        )
        assert (
            set_instance_policies_one_of_set_instance_policy_metrics_model_json2
            == set_instance_policies_one_of_set_instance_policy_metrics_model_json
        )


class TestModel_SetInstancePoliciesOneOfSetInstancePolicyRotation:
    """
    Test Class for SetInstancePoliciesOneOfSetInstancePolicyRotation
    """

    def test_set_instance_policies_one_of_set_instance_policy_rotation_serialization(
        self,
    ):
        """
        Test serialization/deserialization for SetInstancePoliciesOneOfSetInstancePolicyRotation
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        instance_policy_rotation_policy_data_attributes_model = {}  # InstancePolicyRotationPolicyDataAttributes
        instance_policy_rotation_policy_data_attributes_model["interval_month"] = 3

        instance_policy_rotation_policy_data_model = {}  # InstancePolicyRotationPolicyData
        instance_policy_rotation_policy_data_model["enabled"] = True
        instance_policy_rotation_policy_data_model["attributes"] = instance_policy_rotation_policy_data_attributes_model

        set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model = (
            {}
        )  # SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem
        set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model["policy_type"] = "rotation"
        set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model[
            "policy_data"
        ] = instance_policy_rotation_policy_data_model

        # Construct a json representation of a SetInstancePoliciesOneOfSetInstancePolicyRotation model
        set_instance_policies_one_of_set_instance_policy_rotation_model_json = {}
        set_instance_policies_one_of_set_instance_policy_rotation_model_json["metadata"] = collection_metadata_model
        set_instance_policies_one_of_set_instance_policy_rotation_model_json["resources"] = [
            set_instance_policies_one_of_set_instance_policy_rotation_resources_item_model
        ]

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyRotation by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_rotation_model = (
            SetInstancePoliciesOneOfSetInstancePolicyRotation.from_dict(
                set_instance_policies_one_of_set_instance_policy_rotation_model_json
            )
        )
        assert set_instance_policies_one_of_set_instance_policy_rotation_model != False

        # Construct a model instance of SetInstancePoliciesOneOfSetInstancePolicyRotation by calling from_dict on the json representation
        set_instance_policies_one_of_set_instance_policy_rotation_model_dict = (
            SetInstancePoliciesOneOfSetInstancePolicyRotation.from_dict(
                set_instance_policies_one_of_set_instance_policy_rotation_model_json
            ).__dict__
        )
        set_instance_policies_one_of_set_instance_policy_rotation_model2 = (
            SetInstancePoliciesOneOfSetInstancePolicyRotation(
                **set_instance_policies_one_of_set_instance_policy_rotation_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            set_instance_policies_one_of_set_instance_policy_rotation_model
            == set_instance_policies_one_of_set_instance_policy_rotation_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_instance_policies_one_of_set_instance_policy_rotation_model_json2 = (
            set_instance_policies_one_of_set_instance_policy_rotation_model.to_dict()
        )
        assert (
            set_instance_policies_one_of_set_instance_policy_rotation_model_json2
            == set_instance_policies_one_of_set_instance_policy_rotation_model_json
        )


class TestModel_SetInstancePoliciesOneOfSetMultipleInstancePolicies:
    """
    Test Class for SetInstancePoliciesOneOfSetMultipleInstancePolicies
    """

    def test_set_instance_policies_one_of_set_multiple_instance_policies_serialization(
        self,
    ):
        """
        Test serialization/deserialization for SetInstancePoliciesOneOfSetMultipleInstancePolicies
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        set_multiple_instance_policies_resources_item_policy_data_attributes_model = (
            {}
        )  # SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes
        set_multiple_instance_policies_resources_item_policy_data_attributes_model[
            "allowed_network"
        ] = "public-and-private"
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["allowed_ip"] = [
            "10.1.0.0/32",
            "10.0.0.0/24",
            "192.0.2.0/32",
            "198.51.100.0/24",
            "2001:db8::/60",
        ]
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["create_root_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["create_standard_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["import_root_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["import_standard_key"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["enforce_token"] = True
        set_multiple_instance_policies_resources_item_policy_data_attributes_model["interval_month"] = 3

        set_multiple_instance_policies_resources_item_policy_data_model = (
            {}
        )  # SetMultipleInstancePoliciesResourcesItemPolicyData
        set_multiple_instance_policies_resources_item_policy_data_model["enabled"] = True
        set_multiple_instance_policies_resources_item_policy_data_model[
            "attributes"
        ] = set_multiple_instance_policies_resources_item_policy_data_attributes_model

        set_multiple_instance_policies_resources_item_model = {}  # SetMultipleInstancePoliciesResourcesItem
        set_multiple_instance_policies_resources_item_model["policy_type"] = "allowedNetwork"
        set_multiple_instance_policies_resources_item_model[
            "policy_data"
        ] = set_multiple_instance_policies_resources_item_policy_data_model

        # Construct a json representation of a SetInstancePoliciesOneOfSetMultipleInstancePolicies model
        set_instance_policies_one_of_set_multiple_instance_policies_model_json = {}
        set_instance_policies_one_of_set_multiple_instance_policies_model_json["metadata"] = collection_metadata_model
        set_instance_policies_one_of_set_multiple_instance_policies_model_json["resources"] = [
            set_multiple_instance_policies_resources_item_model
        ]

        # Construct a model instance of SetInstancePoliciesOneOfSetMultipleInstancePolicies by calling from_dict on the json representation
        set_instance_policies_one_of_set_multiple_instance_policies_model = (
            SetInstancePoliciesOneOfSetMultipleInstancePolicies.from_dict(
                set_instance_policies_one_of_set_multiple_instance_policies_model_json
            )
        )
        assert set_instance_policies_one_of_set_multiple_instance_policies_model != False

        # Construct a model instance of SetInstancePoliciesOneOfSetMultipleInstancePolicies by calling from_dict on the json representation
        set_instance_policies_one_of_set_multiple_instance_policies_model_dict = (
            SetInstancePoliciesOneOfSetMultipleInstancePolicies.from_dict(
                set_instance_policies_one_of_set_multiple_instance_policies_model_json
            ).__dict__
        )
        set_instance_policies_one_of_set_multiple_instance_policies_model2 = (
            SetInstancePoliciesOneOfSetMultipleInstancePolicies(
                **set_instance_policies_one_of_set_multiple_instance_policies_model_dict
            )
        )

        # Verify the model instances are equivalent
        assert (
            set_instance_policies_one_of_set_multiple_instance_policies_model
            == set_instance_policies_one_of_set_multiple_instance_policies_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_instance_policies_one_of_set_multiple_instance_policies_model_json2 = (
            set_instance_policies_one_of_set_multiple_instance_policies_model.to_dict()
        )
        assert (
            set_instance_policies_one_of_set_multiple_instance_policies_model_json2
            == set_instance_policies_one_of_set_multiple_instance_policies_model_json
        )


class TestModel_SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete:
    """
    Test Class for SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete
    """

    def test_set_key_policies_one_of_set_key_policy_dual_auth_delete_serialization(
        self,
    ):
        """
        Test serialization/deserialization for SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        key_policy_dual_auth_delete_dual_auth_delete_model = {}  # KeyPolicyDualAuthDeleteDualAuthDelete
        key_policy_dual_auth_delete_dual_auth_delete_model["enabled"] = True

        key_policy_dual_auth_delete_model = {}  # KeyPolicyDualAuthDelete
        key_policy_dual_auth_delete_model["type"] = "application/vnd.ibm.kms.policy+json"
        key_policy_dual_auth_delete_model["dualAuthDelete"] = key_policy_dual_auth_delete_dual_auth_delete_model

        # Construct a json representation of a SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete model
        set_key_policies_one_of_set_key_policy_dual_auth_delete_model_json = {}
        set_key_policies_one_of_set_key_policy_dual_auth_delete_model_json["metadata"] = collection_metadata_model
        set_key_policies_one_of_set_key_policy_dual_auth_delete_model_json["resources"] = [
            key_policy_dual_auth_delete_model
        ]

        # Construct a model instance of SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete by calling from_dict on the json representation
        set_key_policies_one_of_set_key_policy_dual_auth_delete_model = (
            SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete.from_dict(
                set_key_policies_one_of_set_key_policy_dual_auth_delete_model_json
            )
        )
        assert set_key_policies_one_of_set_key_policy_dual_auth_delete_model != False

        # Construct a model instance of SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete by calling from_dict on the json representation
        set_key_policies_one_of_set_key_policy_dual_auth_delete_model_dict = (
            SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete.from_dict(
                set_key_policies_one_of_set_key_policy_dual_auth_delete_model_json
            ).__dict__
        )
        set_key_policies_one_of_set_key_policy_dual_auth_delete_model2 = SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete(
            **set_key_policies_one_of_set_key_policy_dual_auth_delete_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            set_key_policies_one_of_set_key_policy_dual_auth_delete_model
            == set_key_policies_one_of_set_key_policy_dual_auth_delete_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_key_policies_one_of_set_key_policy_dual_auth_delete_model_json2 = (
            set_key_policies_one_of_set_key_policy_dual_auth_delete_model.to_dict()
        )
        assert (
            set_key_policies_one_of_set_key_policy_dual_auth_delete_model_json2
            == set_key_policies_one_of_set_key_policy_dual_auth_delete_model_json
        )


class TestModel_SetKeyPoliciesOneOfSetKeyPolicyRotation:
    """
    Test Class for SetKeyPoliciesOneOfSetKeyPolicyRotation
    """

    def test_set_key_policies_one_of_set_key_policy_rotation_serialization(self):
        """
        Test serialization/deserialization for SetKeyPoliciesOneOfSetKeyPolicyRotation
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        key_policy_rotation_rotation_model = {}  # KeyPolicyRotationRotation
        key_policy_rotation_rotation_model["enabled"] = True
        key_policy_rotation_rotation_model["interval_month"] = 1

        key_policy_rotation_model = {}  # KeyPolicyRotation
        key_policy_rotation_model["type"] = "application/vnd.ibm.kms.policy+json"
        key_policy_rotation_model["rotation"] = key_policy_rotation_rotation_model

        # Construct a json representation of a SetKeyPoliciesOneOfSetKeyPolicyRotation model
        set_key_policies_one_of_set_key_policy_rotation_model_json = {}
        set_key_policies_one_of_set_key_policy_rotation_model_json["metadata"] = collection_metadata_model
        set_key_policies_one_of_set_key_policy_rotation_model_json["resources"] = [key_policy_rotation_model]

        # Construct a model instance of SetKeyPoliciesOneOfSetKeyPolicyRotation by calling from_dict on the json representation
        set_key_policies_one_of_set_key_policy_rotation_model = SetKeyPoliciesOneOfSetKeyPolicyRotation.from_dict(
            set_key_policies_one_of_set_key_policy_rotation_model_json
        )
        assert set_key_policies_one_of_set_key_policy_rotation_model != False

        # Construct a model instance of SetKeyPoliciesOneOfSetKeyPolicyRotation by calling from_dict on the json representation
        set_key_policies_one_of_set_key_policy_rotation_model_dict = SetKeyPoliciesOneOfSetKeyPolicyRotation.from_dict(
            set_key_policies_one_of_set_key_policy_rotation_model_json
        ).__dict__
        set_key_policies_one_of_set_key_policy_rotation_model2 = SetKeyPoliciesOneOfSetKeyPolicyRotation(
            **set_key_policies_one_of_set_key_policy_rotation_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            set_key_policies_one_of_set_key_policy_rotation_model
            == set_key_policies_one_of_set_key_policy_rotation_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_key_policies_one_of_set_key_policy_rotation_model_json2 = (
            set_key_policies_one_of_set_key_policy_rotation_model.to_dict()
        )
        assert (
            set_key_policies_one_of_set_key_policy_rotation_model_json2
            == set_key_policies_one_of_set_key_policy_rotation_model_json
        )


class TestModel_SetKeyPoliciesOneOfSetMultipleKeyPolicies:
    """
    Test Class for SetKeyPoliciesOneOfSetMultipleKeyPolicies
    """

    def test_set_key_policies_one_of_set_multiple_key_policies_serialization(self):
        """
        Test serialization/deserialization for SetKeyPoliciesOneOfSetMultipleKeyPolicies
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model["collectionType"] = "application/vnd.ibm.kms.allowed_ip_metadata+json"
        collection_metadata_model["collectionTotal"] = 1

        key_policy_dual_auth_delete_dual_auth_delete_model = {}  # KeyPolicyDualAuthDeleteDualAuthDelete
        key_policy_dual_auth_delete_dual_auth_delete_model["enabled"] = True

        key_policy_rotation_rotation_model = {}  # KeyPolicyRotationRotation
        key_policy_rotation_rotation_model["enabled"] = True
        key_policy_rotation_rotation_model["interval_month"] = 1

        set_multiple_key_policies_resource_model = {}  # SetMultipleKeyPoliciesResource
        set_multiple_key_policies_resource_model["type"] = "application/vnd.ibm.kms.policy+json"
        set_multiple_key_policies_resource_model["dualAuthDelete"] = key_policy_dual_auth_delete_dual_auth_delete_model
        set_multiple_key_policies_resource_model["rotation"] = key_policy_rotation_rotation_model

        # Construct a json representation of a SetKeyPoliciesOneOfSetMultipleKeyPolicies model
        set_key_policies_one_of_set_multiple_key_policies_model_json = {}
        set_key_policies_one_of_set_multiple_key_policies_model_json["metadata"] = collection_metadata_model
        set_key_policies_one_of_set_multiple_key_policies_model_json["resources"] = [
            set_multiple_key_policies_resource_model
        ]

        # Construct a model instance of SetKeyPoliciesOneOfSetMultipleKeyPolicies by calling from_dict on the json representation
        set_key_policies_one_of_set_multiple_key_policies_model = SetKeyPoliciesOneOfSetMultipleKeyPolicies.from_dict(
            set_key_policies_one_of_set_multiple_key_policies_model_json
        )
        assert set_key_policies_one_of_set_multiple_key_policies_model != False

        # Construct a model instance of SetKeyPoliciesOneOfSetMultipleKeyPolicies by calling from_dict on the json representation
        set_key_policies_one_of_set_multiple_key_policies_model_dict = (
            SetKeyPoliciesOneOfSetMultipleKeyPolicies.from_dict(
                set_key_policies_one_of_set_multiple_key_policies_model_json
            ).__dict__
        )
        set_key_policies_one_of_set_multiple_key_policies_model2 = SetKeyPoliciesOneOfSetMultipleKeyPolicies(
            **set_key_policies_one_of_set_multiple_key_policies_model_dict
        )

        # Verify the model instances are equivalent
        assert (
            set_key_policies_one_of_set_multiple_key_policies_model
            == set_key_policies_one_of_set_multiple_key_policies_model2
        )

        # Convert model instance back to dict and verify no loss of data
        set_key_policies_one_of_set_multiple_key_policies_model_json2 = (
            set_key_policies_one_of_set_multiple_key_policies_model.to_dict()
        )
        assert (
            set_key_policies_one_of_set_multiple_key_policies_model_json2
            == set_key_policies_one_of_set_multiple_key_policies_model_json
        )


# endregion
##############################################################################
# End of Model Tests
##############################################################################
