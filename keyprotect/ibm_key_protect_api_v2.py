# coding: utf-8

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

# IBM OpenAPI SDK Code Generator Version: 3.115.0-a8d44b59-20260713-123033

"""
IBM Key Protect helps you provision encrypted keys for apps across IBM Cloud. As you
manage the lifecycle of your keys, you can benefit from knowing that your keys are secured
by cloud-based FIPS 140-2 Level 3 hardware security modules (HSMs) that protect against
theft of information. You can use the Key Protect API to store, generate, and retrieve
your key material. Keys within the service can protect any type of data in your symmetric
key-based encryption solution.

API Version: 2.0.0
"""

from datetime import datetime
from enum import Enum
from typing import BinaryIO, Dict, List, Optional
import base64
import json
import logging

from ibm_cloud_sdk_core import BaseService, DetailedResponse
from ibm_cloud_sdk_core.authenticators.authenticator import Authenticator
from ibm_cloud_sdk_core.get_authenticator import get_authenticator_from_environment
from ibm_cloud_sdk_core.utils import (
    convert_list,
    convert_model,
    datetime_to_string,
    string_to_datetime,
)

from .common import get_sdk_headers

##############################################################################
# Service
##############################################################################


class IbmKeyProtectApiV2(BaseService):
    """The IBM Key Protect API V2 service."""

    DEFAULT_SERVICE_URL = "https://us-south.kms.cloud.ibm.com"
    DEFAULT_SERVICE_NAME = "ibm_key_protect_api"

    PARAMETERIZED_SERVICE_URL = "https://{region}.kms.cloud.ibm.com"

    @classmethod
    def new_instance(
        cls,
        service_name: str = DEFAULT_SERVICE_NAME,
    ) -> "IbmKeyProtectApiV2":
        """
        Return a new client for the IBM Key Protect API service using the specified
               parameters and external configuration.
        """
        authenticator = get_authenticator_from_environment(service_name)
        service = cls(authenticator)
        service.configure_service(service_name)
        return service

    @classmethod
    def construct_service_url(
        cls,
        region: str = "us-south",
    ) -> str:
        """
        Construct a service URL by formatting the parameterized service URL.

        The parameterized service URL is:
        'https://{region}.kms.cloud.ibm.com'

        :param str region: (optional) The region prefix that represents the geographic area where your Key Protect service instance resides.
            (default 'us-south')
        :return: The formatted URL with all variable placeholders replaced by values.
        :rtype: str
        """
        return cls.PARAMETERIZED_SERVICE_URL.format(
            region=region,
        )

    def __init__(
        self,
        authenticator: Authenticator = None,
    ) -> None:
        """
        Construct a new client for the IBM Key Protect API service.

        :param Authenticator authenticator: The authenticator specifies the authentication mechanism.
               Get up to date information from https://github.com/IBM/python-sdk-core/blob/main/README.md
               about initializing the authenticator of your choice.
        """
        BaseService.__init__(
            self, service_url=self.DEFAULT_SERVICE_URL, authenticator=authenticator
        )

    #########################
    # Keys
    #########################

    def get_key_collection_metadata(
        self,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        state: Optional[List[int]] = None,
        extractable: Optional[bool] = None,
        filter: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Retrieve key total.

        Returns the same HTTP headers as a GET request without returning the entity-body.
        This operation returns the number of keys in your instance in a header called
        `Key-Total`.

        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param List[int] state: (optional) The state of the keys to be retrieved.
               States must be a list of integers from 0 to 5 delimited by commas with no
               whitespace or trailing commas. Valid states are based on NIST SP 800-57.
               States are integers and correspond to the Pre-activation = 0, Active = 1,
               Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
               **Usage:** If you want to retrieve active and deleted keys, use
               `../keys?state=1,5`.
        :param bool extractable: (optional) The type of keys to be retrieved.
               Filters keys based on the `extractable` property. You can use this query
               parameter to search for keys whose material can leave the service. If set
               to `true`, standard keys will be retrieved. If set to `false`, root keys
               will be retrieved. If omitted, both root and standard keys will be
               retrieved.
               **Usage:** If you want to retrieve standard keys, use
               `../keys?extractable=true`.
        :param str filter: (optional) When provided, returns the list of keys that
               match the queried properties. Each key property to be filtered on is
               specified as the property name itself, followed by an “=“ symbol, and then
               the value to filter on, followed by a space if there are more properties to
               filter only. Note: Anything between `<` and `>` in the examples or
               descriptions represent placeholder to specify the value
               *Basic format*: <propertyA>=<valueB> <propertyB>=<valueB> - The value to
               filter on may contain a value related to the property itself, or an
               operator followed by a value accepted by the operator - Only one operator
               and value, or one value is accepted per property at a time
               *Format with operator/value pair*: <propertyA>=<operatorA>:<valueA> Up to
               three of the same property may be specified at a time. The key properties
               that can be filtered at this time are:
               - `creationDate`
                 * Date in RFC 3339 format in double-quotes: “2000-03-21T00:00:00Z”
               - `deletionDate`
                 * Date in RFC 3339 format in double-quotes: “2000-03-21T00:00:00Z”
               - `expirationDate`
                 * Date in RFC 3339 format in double-quotes: “2000-03-21T00:00:00Z”
               - `extractable`
                 * Boolean true or false without quotes, case-insensitive
               - `lastRotateDate`
                 * Date in RFC 3339 format in double-quotes: “2000-03-21T00:00:00Z”
               - `lastUpdateDate`
                 * Date in RFC 3339 format in double-quotes: “2000-03-21T00:00:00Z”
               - `state`
                 * A list of comma-separated integers with no space in between: 0,1,2,3,5
               Comparison operations (operators) that can be performed on date values are:
               - `lte:<value>` Less than or equal to - `lt:<value>` Less than -
               `gte:<value>` Greater than or equal to - `gt:<value>` Greater than A
               special keyword for date, `none` (case-insensitive), may be used to
               retreive keys that do not have that property. This is useful for
               `lastRotateDate`, where only keys that have never been rotated can be
               retreived.
               *Examples*:
               - `lastRotateDate="2022-02-15T00:00:00Z"` Filter keys that were last
               rotated on February 15, 2022 - `lastRotateDate=gte:"2022-02-15T00:00:00Z"`
               Filter keys that were last rotated after or on February 15, 2022 -
               `lastRotateDate=gte:"2022-02-15T00:00:00Z"
               lastRotateDate=lt:"2022-03-15T00:00:00Z"` Filter keys that were last
               rotated after or on February 15, 2022 but before (not including) March 15,
               2022 - `lastRotateDate="2022-02-15T00:00:00Z" state=0,1,2,3,5
               extractable=false` Filter root keys that were last rotated on February 15,
               2022, with any state
               *Note*: When you filter by `state` or `extractable` in this query
               parameter, you will not be able to use the deprecated `state` or
               `extractable` independent query parameter. You will get a 400 response code
               if you specify a value for one of the two properties in both this filter
               query parameter and the deprecated independent query of the same name (the
               same applies vice versa).
        :param str x_kms_key_ring: (optional) The ID of the target key ring. If
               unspecified, all resources in the instance that the caller has access to
               will be returned. When the header is specified, only resources within the
               specified key ring, that the caller has access to, will be returned. The
               key ring ID of keys that are created without an `X-Kms-Key-Ring` header is:
               `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_key_collection_metadata",
        )
        headers.update(sdk_headers)

        params = {
            "state": convert_list([str(x) for x in (state or [])]),
            "extractable": extractable,
            "filter": filter,
        }

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]

        url = "/api/v2/keys"
        request = self.prepare_request(
            method="HEAD",
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def create_key(
        self,
        bluemix_instance: str,
        key_create_body: BinaryIO,
        *,
        correlation_id: Optional[str] = None,
        prefer: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create a key.

        Creates a new key with specified key material.
        Key Protect designates the resource as either a root key or a standard key based
        on the `extractable` value that you specify. A successful
        `POST /keys` operation adds the key to the service and returns the details of the
        request in the response entity-body, if the Prefer header is set to
        `return=representation`.

        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param BinaryIO key_create_body: The base request for creating a new key.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str prefer: (optional) Alters server behavior for POST or DELETE
               operations. A header with `return=minimal` causes the service to return
               only the key identifier as metadata. A header containing
               `return=representation` returns both the key material and metadata in the
               response entity-body. If the key has been designated as a root key, the
               system cannot return the key material.
               **Note:** During POST operations, Key Protect may not immediately return
               the key material due to key generation time. To retrieve the key material,
               you can perform a subsequent `GET /keys/{id}` request.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key belongs to. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Key` object
        """

        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        if key_create_body is None:
            raise ValueError("key_create_body must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "Prefer": prefer,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="create_key",
        )
        headers.update(sdk_headers)

        data = key_create_body
        headers["content-type"] = "application/vnd.ibm.kms.key+json"

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        url = "/api/v2/keys"
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_keys(
        self,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        state: Optional[List[int]] = None,
        extractable: Optional[bool] = None,
        search: Optional[str] = None,
        sort: Optional[str] = None,
        filter: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List keys.

        Retrieves a list of keys that are stored in your Key Protect service instance.
        **Important:** When a user of Key Protect on Satellite views lists of keys through
        the [IBM Console](https://cloud.ibm.com/login), or programmatically via this API,
        keys with ["fine grain"
        permissions](/docs/key-protect?topic=key-protect-grant-access-keys#grant-access-key-level)
        won't appear due to the manner in which the service aggregates the collection.
        While the user can still use the key resource, only by using the CLI or API and
        passing the specific key ID can a user access the metadata and other details of
        the key.
        **Note:** `GET /keys` will not return the key material in the response body. You
        can retrieve the key material for a standard key with a subsequent `GET
        /keys/{id}` request.

        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param int limit: (optional) The number of keys to retrieve. By default,
               `GET /keys` returns the first 200 keys. To retrieve a different set of
               keys, use `limit` with `offset` to page through your available resources.
               The maximum value for `limit` is 5,000.
               **Usage:** If you have 20 keys in your instance, and you want to retrieve
               only the first 5 keys, use `../keys?limit=5`.
        :param int offset: (optional) The number of keys to skip. By specifying
               `offset`, you retrieve a subset of keys that starts with the `offset`
               value. Use `offset` with `limit` to page through your available resources.
               **Usage:** If you have 100 keys in your instance, and you want to retrieve
               keys 26 through 50, use `../keys?offset=25&limit=25`.
        :param List[int] state: (optional) The state of the keys to be retrieved.
               States must be a list of integers from 0 to 5 delimited by commas with no
               whitespace or trailing commas. Valid states are based on NIST SP 800-57.
               States are integers and correspond to the Pre-activation = 0, Active = 1,
               Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
               **Usage:** If you want to retrieve active and deleted keys, use
               `../keys?state=1,5`.
        :param bool extractable: (optional) The type of keys to be retrieved.
               Filters keys based on the `extractable` property. You can use this query
               parameter to search for keys whose material can leave the service. If set
               to `true`, standard keys will be retrieved. If set to `false`, root keys
               will be retrieved. If omitted, both root and standard keys will be
               retrieved.
               **Usage:** If you want to retrieve standard keys, use
               `../keys?extractable=true`.
        :param str search: (optional) When provided, performs a search, possibly
               limiting the number of keys returned.
               *Examples*:
                 - `foobar` - find keys where the name or any of its aliases contain
               `foobar`, case insentive (i.e. matches `xfoobar`, `Foobar`).
                 - `fadedbee-0000-0000-0000-1234567890ab` (a valid key id) - find keys
               where the id the key is `fadedbee-0000-0000-0000-1234567890ab`, or the name
               or any of its aliases contain `fadedbee-0000-0000-0000-1234567890ab`, case
               insentive.
               May prepend with options:
                 - `not:` = when specified, inverts matching logic (example: `not:foo`
               will search for keys that have aliases or names that do not contain `foo`)
                 - `escape:` = everything after this option is take as plaintext (example:
               `escape:not:` will search for keys that have an alias or name containing
               the substring `not:`)
                 - `exact:` = only looks for exact matches
               May prepend with search scopes:
                 - `alias:` = search in key aliases for search query
                 - `name:` = search in key names for search query
               *Examples*:
                 - `not:exact:foobar`/`exact:not:foobar` - find keys where the name nor
               any of its aliases are *not* exactly `foobar` (i.e. matches `xfoobar`,
               `bar`, `foo`)
                 - `exact:escape:not:foobar` - find keys where the name or any of its
               aliases are exactly `not:foobar`
                 - `not:alias:foobar`/`alias:not:foobar` - find keys where any of its
               aliases do *not* contain `foobar`
                 - `name:exact:foobar`/`exact:name:foobar` - find keys where the name is
               exactly `foobar`
               *Note*:
                 By default, if no scopes are provided, search will be performed in both
               `name` and `alias` scopes.
                 Search is only possible on a intial searchable space of at most 5000
               keys. If the initial seachable space is greater than 5000 keys, the API
               returns HTTP 400 with the property resouces[0].reasons[0].code equals to
               'KEY_SEARCH_TOO_BROAD'.
                 Use the following filters to reduce the initial searchable space:
                 - `state` (query parameter)
                 - `extractable` (query parameter)
                 - `X-Kms-Key-Ring` (HTTP header)
                 If the total intial searchable space exceeds the 5000 keys limit and when
               providing a fully specified key id or when searching within the `alias`
               scope, a lookup
                 will  be performed and if a key is found, the key will be returned as the
               only resource and in the response metadata the property `incompleteSearch`
               will
                 be `true`.
                 When providing a fully specified key id or when searching within the
               `alias` scope, a key lookup is performed in addition to the search.
                 This means search will try to lookup a single key that is uniquely
               identified by the key id or provided alias, this key will be included in
               the response
                 as the first resource, before other matches.
                 Search scopes are disjunctive, behaving in an *OR* manner. When using
               more than one search scope,
                 a match in at least one of the scopes will result in the key being
               returned.
        :param str sort: (optional) When provided, sorts the list of keys returned
               based on one or more key properties. To sort on a property in descending
               order, prefix the term with "-". To sort on multiple key properties, use a
               comma to separate each properties. The first property in the
               comma-separated list will be evaluated before the next. The key properties
               that can be sorted at this time are:
                 - `id`
                 - `state`
                 - `extractable`
                 - `imported`
                 - `creationDate`
                 - `lastUpdateDate`
                 - `lastRotateDate`
                 - `deletionDate`
                 - `expirationDate`
               The list of keys returned is sorted on id by default, if this parameter is
               not provided.
        :param str filter: (optional) When provided, returns the list of keys that
               match the queried properties. Each key property to be filtered on is
               specified as the property name itself, followed by an “=“ symbol, and then
               the value to filter on, followed by a space if there are more properties to
               filter only. Note: Anything between `<` and `>` in the examples or
               descriptions represent placeholder to specify the value
               *Basic format*: <propertyA>=<valueB> <propertyB>=<valueB> - The value to
               filter on may contain a value related to the property itself, or an
               operator followed by a value accepted by the operator - Only one operator
               and value, or one value is accepted per property at a time
               *Format with operator/value pair*: <propertyA>=<operatorA>:<valueA> Up to
               three of the same property may be specified at a time. The key properties
               that can be filtered at this time are:
               - `creationDate`
                 * Date in RFC 3339 format in double-quotes: “2000-03-21T00:00:00Z”
               - `deletionDate`
                 * Date in RFC 3339 format in double-quotes: “2000-03-21T00:00:00Z”
               - `expirationDate`
                 * Date in RFC 3339 format in double-quotes: “2000-03-21T00:00:00Z”
               - `extractable`
                 * Boolean true or false without quotes, case-insensitive
               - `lastRotateDate`
                 * Date in RFC 3339 format in double-quotes: “2000-03-21T00:00:00Z”
               - `lastUpdateDate`
                 * Date in RFC 3339 format in double-quotes: “2000-03-21T00:00:00Z”
               - `state`
                 * A list of comma-separated integers with no space in between: 0,1,2,3,5
               Comparison operations (operators) that can be performed on date values are:
               - `lte:<value>` Less than or equal to - `lt:<value>` Less than -
               `gte:<value>` Greater than or equal to - `gt:<value>` Greater than A
               special keyword for date, `none` (case-insensitive), may be used to
               retreive keys that do not have that property. This is useful for
               `lastRotateDate`, where only keys that have never been rotated can be
               retreived.
               *Examples*:
               - `lastRotateDate="2022-02-15T00:00:00Z"` Filter keys that were last
               rotated on February 15, 2022 - `lastRotateDate=gte:"2022-02-15T00:00:00Z"`
               Filter keys that were last rotated after or on February 15, 2022 -
               `lastRotateDate=gte:"2022-02-15T00:00:00Z"
               lastRotateDate=lt:"2022-03-15T00:00:00Z"` Filter keys that were last
               rotated after or on February 15, 2022 but before (not including) March 15,
               2022 - `lastRotateDate="2022-02-15T00:00:00Z" state=0,1,2,3,5
               extractable=false` Filter root keys that were last rotated on February 15,
               2022, with any state
               *Note*: When you filter by `state` or `extractable` in this query
               parameter, you will not be able to use the deprecated `state` or
               `extractable` independent query parameter. You will get a 400 response code
               if you specify a value for one of the two properties in both this filter
               query parameter and the deprecated independent query of the same name (the
               same applies vice versa).
        :param str x_kms_key_ring: (optional) The ID of the target key ring. If
               unspecified, all resources in the instance that the caller has access to
               will be returned. When the header is specified, only resources within the
               specified key ring, that the caller has access to, will be returned. The
               key ring ID of keys that are created without an `X-Kms-Key-Ring` header is:
               `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListKeys` object
        """

        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_keys",
        )
        headers.update(sdk_headers)

        params = {
            "limit": limit,
            "offset": offset,
            "state": convert_list([str(x) for x in (state or [])]),
            "extractable": extractable,
            "search": search,
            "sort": sort,
            "filter": filter,
        }

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        url = "/api/v2/keys"
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def create_key_with_policies_overrides(
        self,
        bluemix_instance: str,
        key_with_policy_overrides_create_body: BinaryIO,
        *,
        correlation_id: Optional[str] = None,
        prefer: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create a key with policy overrides.

        Creates a new key with specified key material and key policies. This API overrides
        the policy configurations set at instance level with policies provided in the
        payload. Key Protect designates the resource as a root key or a standard key based
        on the extractable value that you specify. A successful `POST
        /keys_with_policy_overrides` operation adds the key and key policies to the
        service and returns the details of the request in the response entity-body, if the
        Prefer header is set to `return=representation`.

        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param BinaryIO key_with_policy_overrides_create_body: The base request for
               creating a new key with policies.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str prefer: (optional) Alters server behavior for POST or DELETE
               operations. A header with `return=minimal` causes the service to return
               only the key identifier as metadata. A header containing
               `return=representation` returns both the key material and metadata in the
               response entity-body. If the key has been designated as a root key, the
               system cannot return the key material.
               **Note:** During POST operations, Key Protect may not immediately return
               the key material due to key generation time. To retrieve the key material,
               you can perform a subsequent `GET /keys/{id}` request.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key belongs to. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Key` object
        """

        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        if key_with_policy_overrides_create_body is None:
            raise ValueError("key_with_policy_overrides_create_body must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "Prefer": prefer,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="create_key_with_policies_overrides",
        )
        headers.update(sdk_headers)

        data = key_with_policy_overrides_create_body
        headers["content-type"] = "application/vnd.ibm.kms.key+json"

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        url = "/api/v2/keys_with_policy_overrides"
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_key(
        self,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Retrieve a key.

        Retrieves a key and its details by specifying the ID or alias of the key.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetKey` object
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_key",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}".format(**path_param_dict)
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def action_on_key(
        self,
        id: str,
        bluemix_instance: str,
        action: str,
        key_action_body: BinaryIO,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        prefer: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Invoke an action on a key.

        **Note:** This API has been **deprecated** and transitioned to individual request
        paths. Existing actions using this API will continue to be supported, but new
        actions will no longer be added to it. We recommend, if possible, aligning your
        request URLs to the new API path. The generic format of actions is now the
        following:
        `/api/v2/keys/<key_ID>/actions/<action>` where `key_ID` is the key you want to
        operate on/with and `action` is the same action that was passed as a query
        parameter previously.
        Invokes an action on a specified key. This method supports the following actions:
        - `disable`: [Disable
        operations](/docs/key-protect?topic=key-protect-disable-keys) for a key
        - `enable`: [Enable
        operations](/docs/key-protect?topic=key-protect-disable-keys#enable-api) for a key
        - `restore`: [Restore a root
        key](/docs/key-protect?topic=key-protect-restore-keys)
        - `rewrap`: Use a root key to [rewrap or reencrypt a data encryption
        key](/docs/key-protect?topic=key-protect-rewrap-keys)
        - `rotate`: [Create a new
        version](/docs/key-protect?topic=key-protect-rotate-keys) of a root key
        - `setKeyForDeletion`: [Authorize
        deletion](/docs/key-protect?topic=key-protect-delete-dual-auth-keys#set-key-deletion-api)
        for a key with a dual authorization policy
        - `unsetKeyForDeletion`: [Remove an
        authorization](/docs/key-protect?topic=key-protect-delete-dual-auth-keys#unset-key-deletion-api)
        for a key with a dual authorization policy
        - `unwrap`: Use a root key to [unwrap or decrypt a data encryption
        key](/docs/key-protect?topic=key-protect-unwrap-keys)
        - `wrap`: Use a root key to [wrap or encrypt a data encryption
        key](/docs/key-protect?topic=key-protect-wrap-keys)
        **Note:** If you unwrap a wrapped data encryption key (WDEK) that was not wrapped
        by the latest version of the key, the service also returns the a new WDEK, wrapped
        with the latest version of the key as the ciphertext field. The recommendation is
        to store and use that WDEK, although older WDEKs will continue to work.

        :param str id: The v4 UUID that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str action: The action to perform on the specified key.
        :param BinaryIO key_action_body: The base request for key actions.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param str prefer: (optional) Alters server behavior for POST or DELETE
               operations. A header with `return=minimal` causes the service to return
               only the key identifier as metadata. A header containing
               `return=representation` returns both the key material and metadata in the
               response entity-body. If the key has been designated as a root key, the
               system cannot return the key material.
               **Note:** During POST operations, Key Protect may not immediately return
               the key material due to key generation time. To retrieve the key material,
               you can perform a subsequent `GET /keys/{id}` request.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `KeyActionOneOfResponse` object

        Deprecated: this method is deprecated and may be removed in a future release.
        """

        logging.warning("A deprecated operation has been invoked: action_on_key")

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        if not action:
            raise ValueError("action must be provided")
        if key_action_body is None:
            raise ValueError("key_action_body must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
            "Prefer": prefer,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="action_on_key",
        )
        headers.update(sdk_headers)

        params = {
            "action": action,
        }

        data = key_action_body
        headers["content-type"] = "application/vnd.ibm.kms.key_action+json"

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}".format(**path_param_dict)
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
            params=params,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def patch_key(
        self,
        id: str,
        bluemix_instance: str,
        *,
        key_patch_body: Optional[BinaryIO] = None,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update (patch) a key.

        Update attributes of a key. Currently only the following attributes are applicable
        for update: - keyRingID Note: If provided, the `X-Kms-Key-Ring` header should
        specify the key's current key ring. To change the key ring of the key, specify the
        new key ring in the request body.

        :param str id: The v4 UUID that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param BinaryIO key_patch_body: (optional) The base request for patch key.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PatchKeyResponseBody` object
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="patch_key",
        )
        headers.update(sdk_headers)

        data = key_patch_body
        headers["content-type"] = "application/vnd.ibm.kms.key+json"

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}".format(**path_param_dict)
        request = self.prepare_request(
            method="PATCH",
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_key(
        self,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        prefer: Optional[str] = None,
        force: Optional[bool] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete a key.

        Deletes a key by specifying the ID or alias of the key.
        By default, Key Protect requires a single authorization to delete keys. For added
        protection, you can
        [enable a dual authorization policy](#set-key-policies) to safely delete keys from
        your service instance.
        **Important:** After a key has been deleted, any data that is encrypted by the key
        becomes inaccessible, though this can be reversed if the key is restored within
        the 30-day time frame. After 30 days, key metadata, registrations, and policies
        are available for up to 90 days, at which point the key becomes eligible to be
        purged. Note that once a key is no longer restorable and has been purged, its
        associated data can no longer be accessed.
        **Note:** By default, Key Protect blocks the deletion of a key that's protecting a
        cloud resource, such as a Cloud Object Storage bucket. Use
        `GET keys/{id}/registrations` to verify if the key has an active registration to a
        resource. To delete the key and its associated registrations, set the optional
        `force` parameter to `true`.

        :param str id: The v4 UUID that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param str prefer: (optional) Alters server behavior for POST or DELETE
               operations. A header with `return=minimal` causes the service to return
               only the key identifier as metadata. A header containing
               `return=representation` returns both the key material and metadata in the
               response entity-body. If the key has been designated as a root key, the
               system cannot return the key material.
               **Note:** During POST operations, Key Protect may not immediately return
               the key material due to key generation time. To retrieve the key material,
               you can perform a subsequent `GET /keys/{id}` request.
        :param bool force: (optional) If set to `true`, Key Protect forces deletion
               on a key that is protecting a cloud resource, such as a Cloud Object
               Storage bucket. The action removes any registrations that are associated
               with the key.
               **Note:** If a key is protecting a cloud resource that has a retention
               policy, Key Protect cannot delete the key. Use `GET
               keys/{id}/registrations` to review registrations between the key and its
               associated cloud resources. To enable deletion, contact an account owner to
               remove the retention policy on each resource that is associated with this
               key.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `DeleteKey` object
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
            "Prefer": prefer,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="delete_key",
        )
        headers.update(sdk_headers)

        params = {
            "force": force,
        }

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}".format(**path_param_dict)
        request = self.prepare_request(
            method="DELETE",
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_key_metadata(
        self,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Retrieve key metadata.

        Retrieves the details of a key by specifying the ID of the key.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetKeyMetadata` object
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_key_metadata",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/metadata".format(**path_param_dict)
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def purge_key(
        self,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        prefer: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Purge a deleted key.

        Purges all key metadata and registrations associated with the specified key. This
        method requires setting the [_KeyPurge_
        permission](https://cloud.ibm.com/docs/key-protect?topic=key-protect-grant-access-keys#grant-access-keys-specific-functions)
        that is not enabled by default. Purging a key can only be applied to a key in the
        **Destroyed** (5) state. After a key is deleted, there is a wait period of up to
        four hours before purge key operation is allowed.
        **Important:** When you purge a key, you permanently shred its contents and
        associated data. The action cannot be reversed.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param str prefer: (optional) Alters server behavior for POST or DELETE
               operations. A header with `return=minimal` causes the service to return
               only the key identifier as metadata. A header containing
               `return=representation` returns both the key material and metadata in the
               response entity-body. If the key has been designated as a root key, the
               system cannot return the key material.
               **Note:** During POST operations, Key Protect may not immediately return
               the key material due to key generation time. To retrieve the key material,
               you can perform a subsequent `GET /keys/{id}` request.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PurgeKey` object
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
            "Prefer": prefer,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="purge_key",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/purge".format(**path_param_dict)
        request = self.prepare_request(
            method="DELETE",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def restore_key(
        self,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        prefer: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Restore a key.

        [Restore a key](/docs/key-protect?topic=key-protect-restore-keys) that has been
        deleted.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param str prefer: (optional) Alters server behavior for POST or DELETE
               operations. A header with `return=minimal` causes the service to return
               only the key identifier as metadata. A header containing
               `return=representation` returns both the key material and metadata in the
               response entity-body. If the key has been designated as a root key, the
               system cannot return the key material.
               **Note:** During POST operations, Key Protect may not immediately return
               the key material due to key generation time. To retrieve the key material,
               you can perform a subsequent `GET /keys/{id}` request.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
            "Prefer": prefer,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="restore_key",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/vnd.ibm.kms.key+json"

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/restore".format(**path_param_dict)
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def get_key_versions(
        self,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        total_count: Optional[bool] = None,
        all_key_states: Optional[bool] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List key versions.

        Retrieves all versions of a root key by specifying the ID or alias of the key.
        When you rotate a root key, you generate a new version of the key. If you're using
        the root key to protect resources across IBM Cloud, the registered cloud services
        that you associate with the key use the latest key version to wrap your data.
        [Learn more](/docs/key-protect?topic=key-protect-key-rotation).

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param int limit: (optional) The number of key versions to retrieve. By
               default, `GET /versions` returns the first 200 key versions. To retrieve a
               different set of key versions, use `limit` with `offset` to page through
               your available resources. The maximum value for `limit` is 5,000.
               **Usage:** If you have a key with 20 versions in your instance, and you
               want to retrieve only the first 5 versions, use `../versions?limit=5`.
        :param int offset: (optional) The number of key versions to skip. By
               specifying `offset`, you retrieve a subset of key versions that starts with
               the `offset` value. Use `offset` with `limit` to page through your
               available resources.
               **Usage:** If you have a key with 100 versions in your instance, and you
               want to retrieve versions 26 through 50, use
               `../versions?offset=25&limit=25`.
        :param bool total_count: (optional) If set to `true`, returns `totalCount`
               in the response metadata for use with pagination. The `totalCount` value
               returned specifies the total number of key versions that match the request,
               disregarding limit and offset. The default is set to false.
               **Usage:** To return the `totalCount` value for use with pagination, use
               `../versions?totalCount=true`.
        :param bool all_key_states: (optional) If set to `true`, returns the key
               versions of a key in any state. **Usage:** If you have deleted a key and
               still want to retrieve its key versions use
               `../versions?allKeyStates=true`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListKeyVersions` object
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_key_versions",
        )
        headers.update(sdk_headers)

        params = {
            "limit": limit,
            "offset": offset,
            "totalCount": total_count,
            "allKeyStates": all_key_states,
        }

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/versions".format(**path_param_dict)
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # Key actions
    #########################

    def wrap_key(
        self,
        id: str,
        bluemix_instance: str,
        *,
        key_action_wrap_body: Optional[BinaryIO] = None,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Wrap a key.

        Use a root key to [wrap or encrypt a data encryption
        key](/docs/key-protect?topic=key-protect-wrap-keys). When present, the ciphertext
        contains the DEK wrapped by the latest version of the key (WDEK). It is
        recommended to store and use this WDEK in future calls to Key Protect.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param BinaryIO key_action_wrap_body: (optional) The base request for wrap
               key action.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `WrapKeyResponseBody` object
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="wrap_key",
        )
        headers.update(sdk_headers)

        data = key_action_wrap_body
        headers["content-type"] = "application/vnd.ibm.kms.key_action_wrap+json"

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/actions/wrap".format(**path_param_dict)
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def unwrap_key(
        self,
        id: str,
        bluemix_instance: str,
        key_action_unwrap_body: BinaryIO,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Unwrap a key.

        Use a root key to
        [unwrap or decrypt a data encryption
        key](/docs/key-protect?topic=key-protect-unwrap-keys).
        **Note:** When you unwrap a wrapped data encryption key (WDEK) by using a rotated
        root key, the service returns a new ciphertext in the response entity-body. Each
        ciphertext remains available for `unwrap` actions. If you unwrap a DEK with a
        previous ciphertext, the service also returns the latest ciphertext and latest key
        version in the response. Use the latest ciphertext for future unwrap operations.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param BinaryIO key_action_unwrap_body: The base request for unwrap key
               action.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `UnwrapKeyResponseBody` object
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        if key_action_unwrap_body is None:
            raise ValueError("key_action_unwrap_body must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="unwrap_key",
        )
        headers.update(sdk_headers)

        data = key_action_unwrap_body
        headers["content-type"] = "application/vnd.ibm.kms.key_action_unwrap+json"

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/actions/unwrap".format(**path_param_dict)
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def rewrap_key(
        self,
        id: str,
        bluemix_instance: str,
        key_action_rewrap_body: BinaryIO,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Rewrap a key.

        Use a root key to [rewrap or reencrypt a data encryption
        key](/docs/key-protect?topic=key-protect-rewrap-keys).

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param BinaryIO key_action_rewrap_body: The base request for rewrap key
               action.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `RewrapKeyResponseBody` object
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        if key_action_rewrap_body is None:
            raise ValueError("key_action_rewrap_body must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="rewrap_key",
        )
        headers.update(sdk_headers)

        data = key_action_rewrap_body
        headers["content-type"] = "application/vnd.ibm.kms.key_action_rewrap+json"

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/actions/rewrap".format(**path_param_dict)
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def rotate_key(
        self,
        id: str,
        bluemix_instance: str,
        *,
        key_action_rotate_body: Optional[BinaryIO] = None,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        prefer: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Rotate a key.

        [Create a new version](/docs/key-protect?topic=key-protect-rotate-keys) of a root
        key.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param BinaryIO key_action_rotate_body: (optional) The base request for
               rotate key action.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param str prefer: (optional) Alters server behavior for POST or DELETE
               operations. A header with `return=minimal` causes the service to return
               only the key identifier as metadata. A header containing
               `return=representation` returns both the key material and metadata in the
               response entity-body. If the key has been designated as a root key, the
               system cannot return the key material.
               **Note:** During POST operations, Key Protect may not immediately return
               the key material due to key generation time. To retrieve the key material,
               you can perform a subsequent `GET /keys/{id}` request.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
            "Prefer": prefer,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="rotate_key",
        )
        headers.update(sdk_headers)

        data = key_action_rotate_body
        headers["content-type"] = "application/vnd.ibm.kms.key_action_rotate+json"

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/actions/rotate".format(**path_param_dict)
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def set_key_for_deletion(
        self,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Set a key for deletion.

        [Authorize
        deletion](/docs/key-protect?topic=key-protect-delete-dual-auth-keys#set-key-deletion-api)
        for a key with a dual authorization policy.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="set_key_for_deletion",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/actions/setKeyForDeletion".format(**path_param_dict)
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def unset_key_for_deletion(
        self,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Unset a key for deletion.

        [Remove an
        authorization](/docs/key-protect?topic=key-protect-delete-dual-auth-keys#unset-key-deletion-api)
        for a key with a dual authorization policy.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="unset_key_for_deletion",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/actions/unsetKeyForDeletion".format(**path_param_dict)
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def enable_key(
        self,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Enable a key.

        [Enable operations](/docs/key-protect?topic=key-protect-disable-keys#enable-api)
        for a key.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="enable_key",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/actions/enable".format(**path_param_dict)
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def disable_key(
        self,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Disable a key.

        [Disable operations](/docs/key-protect?topic=key-protect-disable-keys) for a key.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="disable_key",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/actions/disable".format(**path_param_dict)
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def sync_associated_resources(
        self,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Sync associated resources.

        Initiate a [manual data
        synchronization](/docs/key-protect?topic=key-protect-sync-associated-resources&interface=api)
        request to the associated resources of a key. Regular key lifecycle events
        automatically notify integrated services of any change. However, in the case a
        service does not respond to a key lifecycle event notification after four hours,
        the
        `sync` API may be used to initiate a renotification to the integrated services
        that manage the associated resources linked to the key.
        **Note:** The services that manage the associated resources linked to the key are
        responsible for maintaining current records of the key state and version. Key
        Protect does not have the ability to force data synchronization for other
        services, which may take up to four hours to complete. The `sync` API is meant to
        **initiate** a request for all associated resources to synchronize their key
        records with the information returned from the Key Protect API.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="sync_associated_resources",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/actions/sync".format(**path_param_dict)
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # Policies
    #########################

    def put_policy(
        self,
        id: str,
        bluemix_instance: str,
        key_policy_put_body: "SetKeyPoliciesOneOf",
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        policy: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Set key policies.

        Creates or updates one or more policies for the specified key.
        You can set policies for a key, such as an
        [automatic rotation
        policy](/docs/key-protect?topic=key-protect-set-rotation-policy) or a
        [dual authorization
        policy](/docs/key-protect?topic=key-protect-set-dual-auth-key-policy) to protect
        against the accidental deletion of keys. Use
        `PUT /keys/{id}/policies` to create new policies for a key or update an existing
        policy.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param SetKeyPoliciesOneOf key_policy_put_body: The base request for key
               policy create or update.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param str policy: (optional) The type of policy that is associated with
               the specified key.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetKeyPoliciesOneOf` object
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        if key_policy_put_body is None:
            raise ValueError("key_policy_put_body must be provided")
        if isinstance(key_policy_put_body, SetKeyPoliciesOneOf):
            key_policy_put_body = convert_model(key_policy_put_body)
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="put_policy",
        )
        headers.update(sdk_headers)

        params = {
            "policy": policy,
        }

        data = json.dumps(key_policy_put_body)
        headers["content-type"] = "application/json"

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/policies".format(**path_param_dict)
        request = self.prepare_request(
            method="PUT",
            url=url,
            headers=headers,
            params=params,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_policy(
        self,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        policy: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List key policies.

        Retrieves a list of policies that are associated with a specified key.
        You can set policies for a key, such as an
        [automatic rotation
        policy](/docs/key-protect?topic=key-protect-set-rotation-policy) or a
        [dual authorization
        policy](/docs/key-protect?topic=key-protect-set-dual-auth-key-policy) to protect
        against the accidental deletion of keys. Use
        `GET /keys/{id}/policies` to browse the policies that exist for a specified key.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param str policy: (optional) The type of policy that is associated with
               the specified key.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetKeyPoliciesOneOf` object
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_policy",
        )
        headers.update(sdk_headers)

        params = {
            "policy": policy,
        }

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/policies".format(**path_param_dict)
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def put_instance_policy(
        self,
        bluemix_instance: str,
        instance_policy_put_body: "SetInstancePoliciesOneOf",
        *,
        correlation_id: Optional[str] = None,
        policy: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Set instance policies.

        Creates or updates one or more policies for the specified service instance.
        **Note:** When you set an instance policy, Key Protect associates the policy
        information with keys that you add to the instance after the policy is updated.
        This operation does not affect existing keys in the instance.

        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param SetInstancePoliciesOneOf instance_policy_put_body: The base request
               for the create or update of instance level policies.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str policy: (optional) The type of policy that is associated with
               the specified instance.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        if instance_policy_put_body is None:
            raise ValueError("instance_policy_put_body must be provided")
        if isinstance(instance_policy_put_body, SetInstancePoliciesOneOf):
            instance_policy_put_body = convert_model(instance_policy_put_body)
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="put_instance_policy",
        )
        headers.update(sdk_headers)

        params = {
            "policy": policy,
        }

        data = json.dumps(instance_policy_put_body)
        headers["content-type"] = "application/json"

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]

        url = "/api/v2/instance/policies"
        request = self.prepare_request(
            method="PUT",
            url=url,
            headers=headers,
            params=params,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_instance_policy(
        self,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        policy: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List instance policies.

        Retrieves a list of policies that are associated with a specified service
        instance.
        You can manage advanced preferences for keys in your service instance by creating
        instance-level policies. Use `GET /instance/policies` to browse the policies that
        are associated with the specified instance. Currently, dual authorization policies
        are supported.

        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str policy: (optional) The type of policy that is associated with
               the specified instance.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetInstancePoliciesOneOf` object
        """

        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_instance_policy",
        )
        headers.update(sdk_headers)

        params = {
            "policy": policy,
        }

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        url = "/api/v2/instance/policies"
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_allowed_ip_port(
        self,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Retrieve allowed IP port.

        Retrieves the private endpoint port associated with your service instance's active
        allowed IP policy. If the instance does not contain an active allowed IP policy,
        no information will be returned.

        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `AllowedIPPort` object
        """

        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_allowed_ip_port",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        url = "/api/v2/instance/allowed_ip_port"
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # Import tokens
    #########################

    def post_import_token(
        self,
        bluemix_instance: str,
        *,
        expiration: Optional[float] = None,
        max_allowed_retrievals: Optional[float] = None,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create an import token.

        Creates an import token that you can use to encrypt and import root keys into the
        service.
        [Learn
        more](/docs/key-protect?topic=key-protect-importing-keys#using-import-tokens).
        When you call `POST /import_token`, Key Protect creates an RSA key-pair from its
        HSMs. The service encrypts and stores the private key in the HSM, and returns the
        corresponding public key when you call
        `GET /import_token`. You can create only one import token per service instance.

        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param float expiration: (optional) The time in seconds from the creation
               of an import token that determines how long its associated public key
               remains valid. The minimum value is `300` seconds (5 minutes), and the
               maximum value is `86400` (24 hours). The default value is `600` (10
               minutes).
        :param float max_allowed_retrievals: (optional) The number of times that an
               import token can be retrieved within its expiration time before it is no
               longer accessible.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key belongs to. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ImportToken` object
        """

        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="post_import_token",
        )
        headers.update(sdk_headers)

        data = {
            "expiration": expiration,
            "maxAllowedRetrievals": max_allowed_retrievals,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers["content-type"] = "application/json"

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        url = "/api/v2/import_token"
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_import_token(
        self,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Retrieve an import token.

        Retrieves the import token that is associated with your service instance.
        When you call `GET /import_token`, Key Protect returns the public key that you can
        use to encrypt and import key material to the service, along with details about
        the key.
        **Note:** After you reach the `maxAllowedRetrievals` or `expirationDate` for the
        import token, the import token and its associated public key can no longer be used
        for key operations. To create a new import token, use
        `POST /import_token`.

        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key belongs to. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetImportToken` object
        """

        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_import_token",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        url = "/api/v2/import_token"
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # Registrations
    #########################

    def get_registrations(
        self,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        url_encoded_resource_crn_query: Optional[str] = None,
        prevent_key_deletion: Optional[bool] = None,
        total_count: Optional[bool] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List registrations for a key.

        Retrieves a list of registrations that are associated with a specified root key.
        When you use a root key to protect an IBM Cloud resource, such as a Cloud Object
        Storage bucket, Key Protect creates a registration between the resource and root
        key. You can use `GET /keys/{id}/registrations` to understand which cloud
        resources are protected by the key that you specify.

        :param str id: The v4 UUID that uniquely identifies the key.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param int limit: (optional) The number of registrations to retrieve. By
               default returns the first 200 registrations. To retrieve a different set of
               registrations, use `limit` with `offset` to page through your available
               resources. The maximum value for `limit` is 5,000.
               **Usage:** If you have 20 registrations that are associated with a key, and
               you want to retrieve only the first 5 registrations, use
               `../registrations?limit=5`.
        :param int offset: (optional) The number of registrations to skip. By
               specifying `offset`, you retrieve a subset of registrations that starts
               with the `offset` value. Use `offset` with `limit` to page through your
               available resources.
               **Usage:** If you have 100 registrations that are associated with a key,
               and you want to retrieve registrations 26 through 50, use
               `../registrations?offset=25&limit=25`.
        :param str url_encoded_resource_crn_query: (optional) Filters for resources
               that are associated with a specified [Cloud Resource
               Name](/docs/account?topic=account-crn) (CRN) by using URL encoded wildcard
               characters (`*`). The parameter should contain all CRN segments and must be
               URL encoded. Supports a prefix search when you specify `*` on the last CRN
               segment.
               **Usage:** To list registrations that are associated with all resources in
               `<service-instance>`, use a URL encoded version of the following string:
               `crn:v1:bluemix:public:<service-name>:<location>:a/<account>:<service-instance>:*:*`.
               To search for subresources, use the following CRN format:
               `crn:v1:bluemix:public:<service-name>:<location>:a/<account>:<service-instance>:<resource-type>:<resource>/<subresource>`.
               For more examples, see [CRN query
               examples](/docs/key-protect?topic=key-protect-view-protected-resources#crn-query-examples).
        :param bool prevent_key_deletion: (optional) Filters registrations based on
               the `preventKeyDeletion` property. You can use this query parameter to
               search for registered cloud resources that are non-erasable due to a
               retention policy. This policy should only be set if a WORM policy
               (https://www.ibm.com/docs/en/spectrum-scale/5.0.1?topic=ics-how-write-once-read-many-worm-storage-works)
               must be satisfied. Do not set this policy by default.
               **Usage:** To search for registered cloud resources that have a retention
               policy, use `../registrations?preventKeyDeletion=true`.
        :param bool total_count: (optional) If set to `true`, returns `totalCount`
               in the response metadata for use with pagination. The `totalCount` value
               returned specifies the total number of registrations that match the
               request, disregarding limit and offset.
               **Usage:** To return the `totalCount` value for use with pagination, use
               `../registrations?totalCount=true`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `RegistrationWithTotalCount` object
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_registrations",
        )
        headers.update(sdk_headers)

        params = {
            "limit": limit,
            "offset": offset,
            "urlEncodedResourceCRNQuery": url_encoded_resource_crn_query,
            "preventKeyDeletion": prevent_key_deletion,
            "totalCount": total_count,
        }

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/registrations".format(**path_param_dict)
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_registrations_all_keys(
        self,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        url_encoded_resource_crn_query: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        prevent_key_deletion: Optional[bool] = None,
        total_count: Optional[bool] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List registrations for any key.

        Retrieves a list of registrations that match the Cloud Resource Name
        (CRN) query that you specify.
        When you use a root key to protect an IBM Cloud resource, such as a Cloud Object
        Storage bucket, Key Protect creates a registration between the resource and root
        key. You can use `GET /keys/registrations` to understand which cloud resources are
        protected by keys in your Key Protect service instance.

        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the target key ring. If
               unspecified, all resources in the instance that the caller has access to
               will be returned. When the header is specified, only resources within the
               specified key ring, that the caller has access to, will be returned. The
               key ring ID of keys that are created without an `X-Kms-Key-Ring` header is:
               `default`.
        :param str url_encoded_resource_crn_query: (optional) Filters for resources
               that are associated with a specified [Cloud Resource
               Name](/docs/account?topic=account-crn) (CRN) by using URL encoded wildcard
               characters (`*`). The parameter should contain all CRN segments and must be
               URL encoded. If provided, the parameter should not contain (`*`) in the
               first eight segments. If this parameter is not provided, registrations for
               all keys in the requested Key Protect instance are returned.
        :param int limit: (optional) The number of registrations to retrieve. By
               default returns the first 200 registrations. To retrieve a different set of
               registrations, use `limit` with `offset` to page through your available
               resources. The maximum value for `limit` is 5,000.
               **Usage:** If you have 20 registrations that are associated with a key, and
               you want to retrieve only the first 5 registrations, use
               `../registrations?limit=5`.
        :param int offset: (optional) The number of registrations to skip. By
               specifying `offset`, you retrieve a subset of registrations that starts
               with the `offset` value. Use `offset` with `limit` to page through your
               available resources.
               **Usage:** If you have 100 registrations that are associated with a key,
               and you want to retrieve registrations 26 through 50, use
               `../registrations?offset=25&limit=25`.
        :param bool prevent_key_deletion: (optional) Filters registrations based on
               the `preventKeyDeletion` property. You can use this query parameter to
               search for registered cloud resources that are non-erasable due to a
               retention policy. This policy should only be set if a WORM policy
               (https://www.ibm.com/docs/en/spectrum-scale/5.0.1?topic=ics-how-write-once-read-many-worm-storage-works)
               must be satisfied. Do not set this policy by default.
               **Usage:** To search for registered cloud resources that have a retention
               policy, use `../registrations?preventKeyDeletion=true`.
        :param bool total_count: (optional) If set to `true`, returns `totalCount`
               in the response metadata for use with pagination. The `totalCount` value
               returned specifies the total number of registrations that match the
               request, disregarding limit and offset.
               **Usage:** To return the `totalCount` value for use with pagination, use
               `../registrations?totalCount=true`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `RegistrationWithTotalCount` object
        """

        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_registrations_all_keys",
        )
        headers.update(sdk_headers)

        params = {
            "urlEncodedResourceCRNQuery": url_encoded_resource_crn_query,
            "limit": limit,
            "offset": offset,
            "preventKeyDeletion": prevent_key_deletion,
            "totalCount": total_count,
        }

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        url = "/api/v2/keys/registrations"
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # Aliases
    #########################

    def create_key_alias(
        self,
        id: str,
        alias: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create an alias.

        Creates a unique alias for the specified key.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str alias: A human-readable alias that uniquely identifies a key.
               Each alias is unique only within the given instance and is not reserved
               across the Key Protect service. Each key can have up to five aliases. There
               is no limit to the number of aliases per instance. The length of the alias
               can be between 2 - 90 characters, inclusive. An alias must be alphanumeric
               and cannot contain spaces or special characters other than '-' or '_'.
               Also, the alias cannot be a version 4 UUID and must not be a Key Protect
               reserved name: `allowed_ip`, `key`, `keys`, `metadata`, `policy`,
               `policies`, `registration`, `registrations`, `ring`, `rings`, `rotate`,
               `wrap`, `unwrap`, `rewrap`, `version`, `versions`.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `KeyAlias` object
        """

        if not id:
            raise ValueError("id must be provided")
        if not alias:
            raise ValueError("alias must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="create_key_alias",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["id", "alias"]
        path_param_values = self.encode_path_vars(id, alias)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/aliases/{alias}".format(**path_param_dict)
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_key_alias(
        self,
        id: str,
        alias: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        x_kms_key_ring: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete an alias.

        Deletes an alias from the associated key.
        Delete alias does not delete the key.

        :param str id: The v4 UUID or alias that uniquely identifies the key.
        :param str alias: A human-readable alias that uniquely identifies a key.
               Each alias is unique only within the given instance and is not reserved
               across the Key Protect service. Each key can have up to five aliases. There
               is no limit to the number of aliases per instance. The length of the alias
               can be between 2 - 90 characters, inclusive. An alias must be alphanumeric
               and cannot contain spaces or special characters other than '-' or '_'.
               Also, the alias cannot be a version 4 UUID and must not be a Key Protect
               reserved name: `allowed_ip`, `key`, `keys`, `metadata`, `policy`,
               `policies`, `registration`, `registrations`, `ring`, `rings`, `rotate`,
               `wrap`, `unwrap`, `rewrap`, `version`, `versions`.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param str x_kms_key_ring: (optional) The ID of the key ring that the
               specified key is a part of. When the header is not specified, Key Protect
               will perform a key ring lookup. For a more optimized request, specify the
               key ring on every call. The key ring ID of keys that are created without an
               `X-Kms-Key-Ring` header is: `default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not id:
            raise ValueError("id must be provided")
        if not alias:
            raise ValueError("alias must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
            "X-Kms-Key-Ring": x_kms_key_ring,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="delete_key_alias",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]

        path_param_keys = ["id", "alias"]
        path_param_values = self.encode_path_vars(id, alias)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/keys/{id}/aliases/{alias}".format(**path_param_dict)
        request = self.prepare_request(
            method="DELETE",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # Key Rings
    #########################

    def list_key_rings(
        self,
        bluemix_instance: str,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        total_count: Optional[bool] = None,
        correlation_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List key rings.

        List all key rings in the instance.

        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param int limit: (optional) The number of key rings to retrieve. By
               default, `GET /key_rings` returns 100 key rings including the default key
               ring. To retrieve a different set of key rings, use `limit` with `offset`
               to page through your available resources. The maximum value for `limit` is
               5,000.
               **Usage:** If you have 20 key rings in your instance, and you want to
               retrieve only the first 5 key rings, use `../key_rings?limit=5`.
        :param int offset: (optional) The number of key rings to skip. By
               specifying `offset`, you retrieve a subset of key rings that starts with
               the `offset` value. Use `offset` with `limit` to page through your
               available resources.
               **Usage:** If you have 20 key rings in your instance, and you want to
               retrieve keys 10 through 20, use `../keys?offset=10&limit=10`.
        :param bool total_count: (optional) If set to `true`, returns `totalCount`
               in the response metadata for use with pagination. The `totalCount` value
               returned specifies the total number of key rings that match the request,
               disregarding limit and offset. The default is set to false.
               **Usage:** To return the `totalCount` value for use with pagination, use
               `../key_rings?totalCount=true`.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListKeyRingsWithTotalCount` object
        """

        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="list_key_rings",
        )
        headers.update(sdk_headers)

        params = {
            "limit": limit,
            "offset": offset,
            "totalCount": total_count,
        }

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        url = "/api/v2/key_rings"
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def create_key_ring(
        self,
        key_ring_id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create a key ring.

        Create a key ring in the instance with the specified name. The key ring ID
        `default` is a reserved key ring ID and cannot be created nor destroyed. The
        `default` key ring is an initial key ring that is generated with each newly
        created instance. All keys not associated with an otherwise specified key ring
        exist within the default key ring.

        :param str key_ring_id: The ID that identifies the key ring. Each ID is
               unique only within the given instance and is not reserved across the Key
               Protect service.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not key_ring_id:
            raise ValueError("key_ring_id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="create_key_ring",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]

        path_param_keys = ["key-ring-id"]
        path_param_values = self.encode_path_vars(key_ring_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/key_rings/{key-ring-id}".format(**path_param_dict)
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_key_ring(
        self,
        key_ring_id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        force: Optional[bool] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete key ring.

        Delete the key ring from the instance. The key ring ID `default` cannot be
        destroyed.

        :param str key_ring_id: The ID that identifies the key ring. Each ID is
               unique only within the given instance and is not reserved across the Key
               Protect service.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param bool force: (optional) Force delete the key ring. All keys in the
               key ring are required to be deleted (in state `5`) before this action can
               be performed. If the key ring to be deleted contains keys, they will be
               moved to the `default` key ring which requires the `kms.secrets.patch` IAM
               action.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not key_ring_id:
            raise ValueError("key_ring_id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="delete_key_ring",
        )
        headers.update(sdk_headers)

        params = {
            "force": force,
        }

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]

        path_param_keys = ["key-ring-id"]
        path_param_values = self.encode_path_vars(key_ring_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/key_rings/{key-ring-id}".format(**path_param_dict)
        request = self.prepare_request(
            method="DELETE",
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # KMIP Adapters
    #########################

    def get_kmip_adapters(
        self,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        total_count: Optional[bool] = None,
        crk_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List KMIP Adapters.

        Retrieves a list of KMIP Adapters.

        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param int limit: (optional) The number of KMIP Adapters to retrieve. By
               default, `GET /kmip_adapters` returns the first 100 KMIP Adapters. To
               retrieve a different set of KMIP adapters, use `limit` with `offset` to
               page through your available resources. The maximum value for `limit` is
               200.
               **Usage:** If you have 20 KMIP Adapters, and you want to retrieve only the
               first 5 adapters, use `../kmip_adapters?limit=5`.
        :param int offset: (optional) The number of KMIP adapters to skip. By
               specifying `offset`, you retrieve a subset of KMIP adapters that starts
               with the `offset` value. Use `offset` with `limit` to page through your
               available resources.
               **Usage:** If you have 20 KMIP Adapters, and you want to retrieve adapters
               11 through 15, use `../kmip_adapters?offset=10&limit=5`.
        :param bool total_count: (optional) If set to `true`, returns `totalCount`
               in the response metadata for use with pagination. The `totalCount` value
               returned specifies the total number of kmip adapters that match the
               request, disregarding limit and offset. The default is set to false.
               **Usage:** To return the `totalCount` value for use with pagination, use
               `../kmip_adapters?totalCount=true`.
        :param str crk_id: (optional) The root key ID(`crk_id`) in the
               `profile_data` to filter on. This field is currently only applicable to
               profile `"native_1.0"`. It will only return adapters with profile_data that
               contains this field. Example usage
               `../kmip_adapters?crk_id=feddecaf-0000-0000-0000-1234567890ab`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListKMIPAdaptersWithTotalCount` object
        """

        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_kmip_adapters",
        )
        headers.update(sdk_headers)

        params = {
            "limit": limit,
            "offset": offset,
            "totalCount": total_count,
            "crk_id": crk_id,
        }

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        url = "/api/v2/kmip_adapters"
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def create_kmip_adapter(
        self,
        bluemix_instance: str,
        metadata: "CollectionMetadata",
        resources: List["CreateKMIPAdapterObject"],
        *,
        correlation_id: Optional[str] = None,
        allow_expiring_key: Optional[bool] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create a KMIP Adapter.

        Creates a KMIP adapter.

        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[CreateKMIPAdapterObject] resources: A collection of resources.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param bool allow_expiring_key: (optional) If set to 'true', allows an
               active root key containing an expiration date to be associated with the
               KMIP adapter.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListKMIPAdapters` object
        """

        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        if metadata is None:
            raise ValueError("metadata must be provided")
        if resources is None:
            raise ValueError("resources must be provided")
        metadata = convert_model(metadata)
        resources = [convert_model(x) for x in resources]
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="create_kmip_adapter",
        )
        headers.update(sdk_headers)

        params = {
            "allowExpiringKey": allow_expiring_key,
        }

        data = {
            "metadata": metadata,
            "resources": resources,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers["content-type"] = "application/json"

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        url = "/api/v2/kmip_adapters"
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
            params=params,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_kmip_adapter(
        self,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Retrieve a KMIP Adapter.

        Retrieves a KMIP adapter using its id / name.

        :param str id: The name or v4 UUID of the KMIP Adapter that uniquely
               identifies it.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListKMIPAdapters` object
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_kmip_adapter",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/kmip_adapters/{id}".format(**path_param_dict)
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_kmip_adapter(
        self,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete a KMIP Adapter.

        Deletes a KMIP Adapter, including all its client certificates, with the given id /
        name.

        :param str id: The name or v4 UUID of the KMIP Adapter that uniquely
               identifies it.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="delete_kmip_adapter",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]

        path_param_keys = ["id"]
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/kmip_adapters/{id}".format(**path_param_dict)
        request = self.prepare_request(
            method="DELETE",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def get_kmip_objects(
        self,
        adapter_id: str,
        bluemix_instance: str,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        total_count: Optional[bool] = None,
        state: Optional[List[int]] = None,
        correlation_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List KMIP objects of a KMIP Adapter.

        List KMIP objects of a KMIP Adapter.

        :param str adapter_id: The name or v4 UUID of the KMIP Adapter that
               uniquely identifies it.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param int limit: (optional) The number of kmip objects to retrieve. By
               default, `GET /kmip_adapters/{id}/kmip_objects` returns the first 100
               kmip_objects. To retrieve a different set of kmip objects, use `limit` with
               `offset` to page through your available resources. The maximum value for
               `limit` is 5000.
               **Usage:** If you have 20 kmip objects associated with your KMIP adapter,
               and you want to retrieve only the first 5 kmip objects, use
               `../kmip_adapters/{id}/kmip_objects?limit=5`.
        :param int offset: (optional) The number of kmip objects to skip. By
               specifying `offset`, you retrieve a subset of kmip objects that starts with
               the `offset` value. Use `offset` with `limit` to page through your
               available resources.
               **Usage:** If you have 20 kmip objects associated with your KMIP adapter,
               and you want to retrieve kmip objects 11 through 15, use
               `../kmip_adapters/{id}/kmip_objects?offset=10&limit=5`.
        :param bool total_count: (optional) If set to `true`, returns `totalCount`
               in the response metadata for use with pagination. The `totalCount` value
               returned specifies the total number of kmip objects that match the request,
               disregarding limit and offset. The default is set to false. **Usage:** To
               return the `totalCount` value for use with pagination, use
               `../kmip_adapters/{id}/kmip_objects?totalCount=true`.
        :param List[int] state: (optional) List of states to filter the KMIP
               objects on. The `default` is set to `[1,2,3,4]`. States are integers and
               correspond to Pre-Active = 1, Active = 2, Deactivated = 3, Compromised = 4,
               Destroyed = 5, Destroyed Compromised = 6. **Usage:** To filter on multiples
               `state` values, use `../kmip_adapters/{id}/kmip_objects?state=2,3`.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListKMIPObjectsWithTotalCount` object
        """

        if not adapter_id:
            raise ValueError("adapter_id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_kmip_objects",
        )
        headers.update(sdk_headers)

        params = {
            "limit": limit,
            "offset": offset,
            "totalCount": total_count,
            "state": convert_list([str(x) for x in (state or [])]),
        }

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["adapter_id"]
        path_param_values = self.encode_path_vars(adapter_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/kmip_adapters/{adapter_id}/kmip_objects".format(
            **path_param_dict
        )
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_kmip_object(
        self,
        adapter_id: str,
        bluemix_instance: str,
        id: str,
        *,
        correlation_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Retrieve a KMIP object from a KMIP Adapter.

        Retrieves a KMIP object from a KMIP Adapter by its id.

        :param str adapter_id: The name or v4 UUID of the KMIP Adapter that
               uniquely identifies it.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str id: The v4 UUID of the kmip object that uniquely identifies it.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListKMIPObjectsWithTotalCount` object
        """

        if not adapter_id:
            raise ValueError("adapter_id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        if not id:
            raise ValueError("id must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_kmip_object",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["adapter_id", "id"]
        path_param_values = self.encode_path_vars(adapter_id, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/kmip_adapters/{adapter_id}/kmip_objects/{id}".format(
            **path_param_dict
        )
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_kmip_object(
        self,
        adapter_id: str,
        bluemix_instance: str,
        id: str,
        *,
        correlation_id: Optional[str] = None,
        force: Optional[bool] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete a KMIP object from a KMIP Adapter.

        Deletes a KMIP object from a KMIP Adapter given its id. Changes the state of the
        KMIP object to 5 (Destroyed) and erases its key material. Any data encrypted by
        this KMIP object will be crypto erased when the KMIP Object changes it state to 5
        (Destroyed).

        :param str adapter_id: The name or v4 UUID of the KMIP Adapter that
               uniquely identifies it.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str id: The name or v4 UUID of the client certificate that uniquely
               identifies it.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param bool force: (optional) Force delete the KMIP object, regardless of
               the object's state. All object data is eligible to be purged 90 days after
               deletion.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not adapter_id:
            raise ValueError("adapter_id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        if not id:
            raise ValueError("id must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="delete_kmip_object",
        )
        headers.update(sdk_headers)

        params = {
            "force": force,
        }

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]

        path_param_keys = ["adapter_id", "id"]
        path_param_values = self.encode_path_vars(adapter_id, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/kmip_adapters/{adapter_id}/kmip_objects/{id}".format(
            **path_param_dict
        )
        request = self.prepare_request(
            method="DELETE",
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_kmip_client_certificates(
        self,
        adapter_id: str,
        bluemix_instance: str,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        total_count: Optional[bool] = None,
        correlation_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List client certificates of a KMIP Adapter.

        List client certificates of a KMIP Adapter.

        :param str adapter_id: The name or v4 UUID of the KMIP Adapter that
               uniquely identifies it.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param int limit: (optional) The number of client certificates to retrieve.
               By default, `GET /kmip_adapters/{id}/certificates` returns the first 100
               certificates. To retrieve a different set of certificates, use `limit` with
               `offset` to page through your available resources. The maximum value for
               `limit` is 200.
               **Usage:** If you have 20 certificates associated with your KMIP adapter,
               and you want to retrieve only the first 5 certificates, use
               `../kmip_adapters/{id}/certificates?limit=5`.
        :param int offset: (optional) The number of client certificates to skip. By
               specifying `offset`, you retrieve a subset of certificates that starts with
               the `offset` value. Use `offset` with `limit` to page through your
               available resources.
               **Usage:** If you have 20 certificates associated with your KMIP adapter,
               and you want to retrieve certificates 11 through 15, use
               `../kmip_adapters/{id}/certificates?offset=10&limit=5`.
        :param bool total_count: (optional) If set to `true`, returns `totalCount`
               in the response metadata for use with pagination. The `totalCount` value
               returned specifies the total number of client certificates that match the
               request, disregarding limit and offset. The default is set to false.
               **Usage:** To return the `totalCount` value for use with pagination, use
               `../kmip_adapters/{id}/certificates?totalCount=true`.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListKMIPPartialClientCertificatesWithTotalCount` object
        """

        if not adapter_id:
            raise ValueError("adapter_id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_kmip_client_certificates",
        )
        headers.update(sdk_headers)

        params = {
            "limit": limit,
            "offset": offset,
            "totalCount": total_count,
        }

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["adapter_id"]
        path_param_values = self.encode_path_vars(adapter_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/kmip_adapters/{adapter_id}/certificates".format(
            **path_param_dict
        )
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def add_kmip_client_certificate(
        self,
        adapter_id: str,
        bluemix_instance: str,
        metadata: "CollectionMetadata",
        resources: List["CreateKMIPClientCertificateObject"],
        *,
        correlation_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Add a client certificate to a KMIP Adapter.

        Add a client certificate to a KMIP Adapter. It might take up to 5 minutes for a
        KMIP call using the newly add certificate to pass authentication. A maximum of 200
        client certificates can be associated with a KMIP Adapter at a time.

        :param str adapter_id: The name or v4 UUID of the KMIP Adapter that
               uniquely identifies it.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[CreateKMIPClientCertificateObject] resources: A collection of
               resources.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListKMIPClientCertificates` object
        """

        if not adapter_id:
            raise ValueError("adapter_id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        if metadata is None:
            raise ValueError("metadata must be provided")
        if resources is None:
            raise ValueError("resources must be provided")
        metadata = convert_model(metadata)
        resources = [convert_model(x) for x in resources]
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="add_kmip_client_certificate",
        )
        headers.update(sdk_headers)

        data = {
            "metadata": metadata,
            "resources": resources,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers["content-type"] = "application/json"

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["adapter_id"]
        path_param_values = self.encode_path_vars(adapter_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/kmip_adapters/{adapter_id}/certificates".format(
            **path_param_dict
        )
        request = self.prepare_request(
            method="POST",
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_kmip_client_certificate(
        self,
        adapter_id: str,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Retrieve a client certificate from a KMIP Adapter.

        Retrieves a client certificate from a KMIP Adapter using its id / name.

        :param str adapter_id: The name or v4 UUID of the KMIP Adapter that
               uniquely identifies it.
        :param str id: The name or v4 UUID of the client certificate that uniquely
               identifies it.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListKMIPClientCertificates` object
        """

        if not adapter_id:
            raise ValueError("adapter_id must be provided")
        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="get_kmip_client_certificate",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]
        headers["Accept"] = "application/json"

        path_param_keys = ["adapter_id", "id"]
        path_param_values = self.encode_path_vars(adapter_id, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/kmip_adapters/{adapter_id}/certificates/{id}".format(
            **path_param_dict
        )
        request = self.prepare_request(
            method="GET",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_kmip_client_certificate(
        self,
        adapter_id: str,
        id: str,
        bluemix_instance: str,
        *,
        correlation_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete a client certificate from a KMIP Adapter.

        Removes a client certificate from a KMIP Adapter given its id / name. It might
        take up to 5 minutes for a KMIP call using deleted certificate to fail
        authentication.

        :param str adapter_id: The name or v4 UUID of the KMIP Adapter that
               uniquely identifies it.
        :param str id: The name or v4 UUID of the client certificate that uniquely
               identifies it.
        :param str bluemix_instance: The IBM Cloud instance ID that identifies your
               Key Protect service instance.
        :param str correlation_id: (optional) The v4 UUID used to correlate and
               track transactions.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not adapter_id:
            raise ValueError("adapter_id must be provided")
        if not id:
            raise ValueError("id must be provided")
        if not bluemix_instance:
            raise ValueError("bluemix_instance must be provided")
        headers = {
            "Bluemix-Instance": bluemix_instance,
            "Correlation-Id": correlation_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version="V2",
            operation_id="delete_kmip_client_certificate",
        )
        headers.update(sdk_headers)

        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            del kwargs["headers"]

        path_param_keys = ["adapter_id", "id"]
        path_param_values = self.encode_path_vars(adapter_id, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = "/api/v2/kmip_adapters/{adapter_id}/certificates/{id}".format(
            **path_param_dict
        )
        request = self.prepare_request(
            method="DELETE",
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response


class CreateKeyEnums:
    """
    Enums for create_key parameters.
    """

    class Prefer(str, Enum):
        """
        Alters server behavior for POST or DELETE operations. A header with
        `return=minimal` causes the service to return only the key identifier as metadata.
        A header containing `return=representation` returns both the key material and
        metadata in the response entity-body. If the key has been designated as a root
        key, the system cannot return the key material.
        **Note:** During POST operations, Key Protect may not immediately return the key
        material due to key generation time. To retrieve the key material, you can perform
        a subsequent `GET /keys/{id}` request.
        """

        RETURN_REPRESENTATION = "return=representation"
        RETURN_MINIMAL = "return=minimal"


class GetKeysEnums:
    """
    Enums for get_keys parameters.
    """

    class Sort(str, Enum):
        """
        When provided, sorts the list of keys returned based on one or more key
        properties. To sort on a property in descending order, prefix the term with "-".
        To sort on multiple key properties, use a comma to separate each properties. The
        first property in the comma-separated list will be evaluated before the next. The
        key properties that can be sorted at this time are:
          - `id`
          - `state`
          - `extractable`
          - `imported`
          - `creationDate`
          - `lastUpdateDate`
          - `lastRotateDate`
          - `deletionDate`
          - `expirationDate`
        The list of keys returned is sorted on id by default, if this parameter is not
        provided.
        """

        ID = "id"
        STATE = "state"
        EXTRACTABLE = "extractable"
        IMPORTED = "imported"
        CREATIONDATE = "creationDate"
        LASTUPDATEDATE = "lastUpdateDate"
        LASTROTATEDATE = "lastRotateDate"
        DELETIONDATE = "deletionDate"
        EXPIRATIONDATE = "expirationDate"


class CreateKeyWithPoliciesOverridesEnums:
    """
    Enums for create_key_with_policies_overrides parameters.
    """

    class Prefer(str, Enum):
        """
        Alters server behavior for POST or DELETE operations. A header with
        `return=minimal` causes the service to return only the key identifier as metadata.
        A header containing `return=representation` returns both the key material and
        metadata in the response entity-body. If the key has been designated as a root
        key, the system cannot return the key material.
        **Note:** During POST operations, Key Protect may not immediately return the key
        material due to key generation time. To retrieve the key material, you can perform
        a subsequent `GET /keys/{id}` request.
        """

        RETURN_REPRESENTATION = "return=representation"
        RETURN_MINIMAL = "return=minimal"


class ActionOnKeyEnums:
    """
    Enums for action_on_key parameters.
    """

    class Action(str, Enum):
        """
        The action to perform on the specified key.
        """

        DISABLE = "disable"
        ENABLE = "enable"
        RESTORE = "restore"
        REWRAP = "rewrap"
        ROTATE = "rotate"
        SETKEYFORDELETION = "setKeyForDeletion"
        UNSETKEYFORDELETION = "unsetKeyForDeletion"
        UNWRAP = "unwrap"
        WRAP = "wrap"

    class Prefer(str, Enum):
        """
        Alters server behavior for POST or DELETE operations. A header with
        `return=minimal` causes the service to return only the key identifier as metadata.
        A header containing `return=representation` returns both the key material and
        metadata in the response entity-body. If the key has been designated as a root
        key, the system cannot return the key material.
        **Note:** During POST operations, Key Protect may not immediately return the key
        material due to key generation time. To retrieve the key material, you can perform
        a subsequent `GET /keys/{id}` request.
        """

        RETURN_REPRESENTATION = "return=representation"
        RETURN_MINIMAL = "return=minimal"


class DeleteKeyEnums:
    """
    Enums for delete_key parameters.
    """

    class Prefer(str, Enum):
        """
        Alters server behavior for POST or DELETE operations. A header with
        `return=minimal` causes the service to return only the key identifier as metadata.
        A header containing `return=representation` returns both the key material and
        metadata in the response entity-body. If the key has been designated as a root
        key, the system cannot return the key material.
        **Note:** During POST operations, Key Protect may not immediately return the key
        material due to key generation time. To retrieve the key material, you can perform
        a subsequent `GET /keys/{id}` request.
        """

        RETURN_REPRESENTATION = "return=representation"
        RETURN_MINIMAL = "return=minimal"


class PurgeKeyEnums:
    """
    Enums for purge_key parameters.
    """

    class Prefer(str, Enum):
        """
        Alters server behavior for POST or DELETE operations. A header with
        `return=minimal` causes the service to return only the key identifier as metadata.
        A header containing `return=representation` returns both the key material and
        metadata in the response entity-body. If the key has been designated as a root
        key, the system cannot return the key material.
        **Note:** During POST operations, Key Protect may not immediately return the key
        material due to key generation time. To retrieve the key material, you can perform
        a subsequent `GET /keys/{id}` request.
        """

        RETURN_REPRESENTATION = "return=representation"
        RETURN_MINIMAL = "return=minimal"


class RestoreKeyEnums:
    """
    Enums for restore_key parameters.
    """

    class Prefer(str, Enum):
        """
        Alters server behavior for POST or DELETE operations. A header with
        `return=minimal` causes the service to return only the key identifier as metadata.
        A header containing `return=representation` returns both the key material and
        metadata in the response entity-body. If the key has been designated as a root
        key, the system cannot return the key material.
        **Note:** During POST operations, Key Protect may not immediately return the key
        material due to key generation time. To retrieve the key material, you can perform
        a subsequent `GET /keys/{id}` request.
        """

        RETURN_REPRESENTATION = "return=representation"
        RETURN_MINIMAL = "return=minimal"


class RotateKeyEnums:
    """
    Enums for rotate_key parameters.
    """

    class Prefer(str, Enum):
        """
        Alters server behavior for POST or DELETE operations. A header with
        `return=minimal` causes the service to return only the key identifier as metadata.
        A header containing `return=representation` returns both the key material and
        metadata in the response entity-body. If the key has been designated as a root
        key, the system cannot return the key material.
        **Note:** During POST operations, Key Protect may not immediately return the key
        material due to key generation time. To retrieve the key material, you can perform
        a subsequent `GET /keys/{id}` request.
        """

        RETURN_REPRESENTATION = "return=representation"
        RETURN_MINIMAL = "return=minimal"


class PutPolicyEnums:
    """
    Enums for put_policy parameters.
    """

    class Policy(str, Enum):
        """
        The type of policy that is associated with the specified key.
        """

        DUALAUTHDELETE = "dualAuthDelete"
        ROTATION = "rotation"


class GetPolicyEnums:
    """
    Enums for get_policy parameters.
    """

    class Policy(str, Enum):
        """
        The type of policy that is associated with the specified key.
        """

        DUALAUTHDELETE = "dualAuthDelete"
        ROTATION = "rotation"


class PutInstancePolicyEnums:
    """
    Enums for put_instance_policy parameters.
    """

    class Policy(str, Enum):
        """
        The type of policy that is associated with the specified instance.
        """

        ALLOWEDNETWORK = "allowedNetwork"
        DUALAUTHDELETE = "dualAuthDelete"
        ALLOWEDIP = "allowedIP"
        KEYCREATEIMPORTACCESS = "keyCreateImportAccess"
        METRICS = "metrics"
        ROTATION = "rotation"


class GetInstancePolicyEnums:
    """
    Enums for get_instance_policy parameters.
    """

    class Policy(str, Enum):
        """
        The type of policy that is associated with the specified instance.
        """

        ALLOWEDNETWORK = "allowedNetwork"
        DUALAUTHDELETE = "dualAuthDelete"
        ALLOWEDIP = "allowedIP"
        KEYCREATEIMPORTACCESS = "keyCreateImportAccess"
        METRICS = "metrics"
        ROTATION = "rotation"


##############################################################################
# Models
##############################################################################


class AllowedIPPort:
    """
    Properties associated with the port associated with an instance with an allowed IP
    policy.

    :param CollectionMetadata metadata: (optional) The metadata that describes the
          resource array.
    :param List[AllowedIPPortResource] resources: (optional) A collection of
          resources.
    """

    def __init__(
        self,
        *,
        metadata: Optional["CollectionMetadata"] = None,
        resources: Optional[List["AllowedIPPortResource"]] = None,
    ) -> None:
        """
        Initialize a AllowedIPPort object.

        :param CollectionMetadata metadata: (optional) The metadata that describes
               the resource array.
        :param List[AllowedIPPortResource] resources: (optional) A collection of
               resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "AllowedIPPort":
        """Initialize a AllowedIPPort object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [AllowedIPPortResource.from_dict(v) for v in resources]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a AllowedIPPort object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this AllowedIPPort object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "AllowedIPPort") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "AllowedIPPort") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class AllowedIPPortResource:
    """
    Metadata of the port associated with an instance with an allowed IP policy.

    :param int private_endpoint_port: (optional) The port required to access an
          instance with an allowed IP policy via the Key Protect private service endpoint.
          Cannot be used with the Key Protect public service endpoint. For more
          information, see [accessing an instance via private
          endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-private-endpoint)
          for instructions on how to use the `private_endpoint_port` value.
    """

    def __init__(
        self,
        *,
        private_endpoint_port: Optional[int] = None,
    ) -> None:
        """
        Initialize a AllowedIPPortResource object.

        """
        self.private_endpoint_port = private_endpoint_port

    @classmethod
    def from_dict(cls, _dict: Dict) -> "AllowedIPPortResource":
        """Initialize a AllowedIPPortResource object from a json dictionary."""
        args = {}
        if (private_endpoint_port := _dict.get("private_endpoint_port")) is not None:
            args["private_endpoint_port"] = private_endpoint_port
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a AllowedIPPortResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if (
            hasattr(self, "private_endpoint_port")
            and getattr(self, "private_endpoint_port") is not None
        ):
            _dict["private_endpoint_port"] = getattr(self, "private_endpoint_port")
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this AllowedIPPortResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "AllowedIPPortResource") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "AllowedIPPortResource") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CollectionMetadata:
    """
    The metadata that describes the resource array.

    :param str collection_type: The type of resources in the resource array.
    :param int collection_total: The number of elements in the resource array.
    """

    def __init__(
        self,
        collection_type: str,
        collection_total: int,
    ) -> None:
        """
        Initialize a CollectionMetadata object.

        :param str collection_type: The type of resources in the resource array.
        :param int collection_total: The number of elements in the resource array.
        """
        self.collection_type = collection_type
        self.collection_total = collection_total

    @classmethod
    def from_dict(cls, _dict: Dict) -> "CollectionMetadata":
        """Initialize a CollectionMetadata object from a json dictionary."""
        args = {}
        if (collection_type := _dict.get("collectionType")) is not None:
            args["collection_type"] = collection_type
        else:
            raise ValueError(
                "Required property 'collectionType' not present in CollectionMetadata JSON"
            )
        if (collection_total := _dict.get("collectionTotal")) is not None:
            args["collection_total"] = collection_total
        else:
            raise ValueError(
                "Required property 'collectionTotal' not present in CollectionMetadata JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CollectionMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "collection_type") and self.collection_type is not None:
            _dict["collectionType"] = self.collection_type
        if hasattr(self, "collection_total") and self.collection_total is not None:
            _dict["collectionTotal"] = self.collection_total
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CollectionMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "CollectionMetadata") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "CollectionMetadata") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class CollectionTypeEnum(str, Enum):
        """
        The type of resources in the resource array.
        """

        APPLICATION_VND_IBM_KMS_ALLOWED_IP_METADATA_JSON = (
            "application/vnd.ibm.kms.allowed_ip_metadata+json"
        )
        APPLICATION_VND_IBM_KMS_CRN_JSON = "application/vnd.ibm.kms.crn+json"
        APPLICATION_VND_IBM_KMS_ERROR_JSON = "application/vnd.ibm.kms.error+json"
        APPLICATION_VND_IBM_KMS_EVENT_ACKNOWLEDGE_JSON = (
            "application/vnd.ibm.kms.event_acknowledge+json"
        )
        APPLICATION_VND_IBM_KMS_IMPORT_TOKEN_JSON = (
            "application/vnd.ibm.kms.import_token+json"
        )
        APPLICATION_VND_IBM_KMS_KEY_JSON = "application/vnd.ibm.kms.key+json"
        APPLICATION_VND_IBM_KMS_KEY_ACTION_JSON = (
            "application/vnd.ibm.kms.key_action+json"
        )
        APPLICATION_VND_IBM_KMS_ALIAS_JSON = "application/vnd.ibm.kms.alias+json"
        APPLICATION_VND_IBM_KMS_KEY_RING_JSON = "application/vnd.ibm.kms.key_ring+json"
        APPLICATION_VND_IBM_KMS_POLICY_JSON = "application/vnd.ibm.kms.policy+json"
        APPLICATION_VND_IBM_KMS_REGISTRATION_INPUT_JSON = (
            "application/vnd.ibm.kms.registration_input+json"
        )
        APPLICATION_VND_IBM_KMS_REGISTRATION_JSON = (
            "application/vnd.ibm.kms.registration+json"
        )
        APPLICATION_VND_IBM_KMS_RESOURCE_CRN_JSON = (
            "application/vnd.ibm.kms.resource_crn+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_ADAPTER_JSON = (
            "application/vnd.ibm.kms.kmip_adapter+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_CLIENT_CERTIFICATE_JSON = (
            "application/vnd.ibm.kms.kmip_client_certificate+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_OBJECT_JSON = (
            "application/vnd.ibm.kms.kmip_object+json"
        )


class CollectionMetadataListKeys:
    """
    The metadata that describes the list keys response.

    :param str collection_type: The type of resources in the resource array.
    :param int collection_total: The number of elements in the resource array.
    :param bool incomplete_search: (optional) If present, indicates the search did
          not complete due to the searchable set of keys being too large. Please retry
          your request with additional or more specific filters (i.e. extractable, state,
          etc.). To determine the size of the searchable set of keys, please use `HEAD
          /api/v2/keys` with the desired search filters. For a search to be performmed,
          the resulting set contain at most 5000 keys.
    :param ListKeysMetadataPropertiesSearchQuery search_query: (optional) Represents
          the parsed search query used for matching logic. Only returned when a search is
          requested.
    """

    def __init__(
        self,
        collection_type: str,
        collection_total: int,
        *,
        incomplete_search: Optional[bool] = None,
        search_query: Optional["ListKeysMetadataPropertiesSearchQuery"] = None,
    ) -> None:
        """
        Initialize a CollectionMetadataListKeys object.

        :param str collection_type: The type of resources in the resource array.
        :param int collection_total: The number of elements in the resource array.
        :param bool incomplete_search: (optional) If present, indicates the search
               did not complete due to the searchable set of keys being too large. Please
               retry your request with additional or more specific filters (i.e.
               extractable, state, etc.). To determine the size of the searchable set of
               keys, please use `HEAD /api/v2/keys` with the desired search filters. For a
               search to be performmed, the resulting set contain at most 5000 keys.
        :param ListKeysMetadataPropertiesSearchQuery search_query: (optional)
               Represents the parsed search query used for matching logic. Only returned
               when a search is requested.
        """
        self.collection_type = collection_type
        self.collection_total = collection_total
        self.incomplete_search = incomplete_search
        self.search_query = search_query

    @classmethod
    def from_dict(cls, _dict: Dict) -> "CollectionMetadataListKeys":
        """Initialize a CollectionMetadataListKeys object from a json dictionary."""
        args = {}
        if (collection_type := _dict.get("collectionType")) is not None:
            args["collection_type"] = collection_type
        else:
            raise ValueError(
                "Required property 'collectionType' not present in CollectionMetadataListKeys JSON"
            )
        if (collection_total := _dict.get("collectionTotal")) is not None:
            args["collection_total"] = collection_total
        else:
            raise ValueError(
                "Required property 'collectionTotal' not present in CollectionMetadataListKeys JSON"
            )
        if (incomplete_search := _dict.get("incompleteSearch")) is not None:
            args["incomplete_search"] = incomplete_search
        if (search_query := _dict.get("searchQuery")) is not None:
            args["search_query"] = ListKeysMetadataPropertiesSearchQuery.from_dict(
                search_query
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CollectionMetadataListKeys object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "collection_type") and self.collection_type is not None:
            _dict["collectionType"] = self.collection_type
        if hasattr(self, "collection_total") and self.collection_total is not None:
            _dict["collectionTotal"] = self.collection_total
        if hasattr(self, "incomplete_search") and self.incomplete_search is not None:
            _dict["incompleteSearch"] = self.incomplete_search
        if hasattr(self, "search_query") and self.search_query is not None:
            if isinstance(self.search_query, dict):
                _dict["searchQuery"] = self.search_query
            else:
                _dict["searchQuery"] = self.search_query.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CollectionMetadataListKeys object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "CollectionMetadataListKeys") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "CollectionMetadataListKeys") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class CollectionTypeEnum(str, Enum):
        """
        The type of resources in the resource array.
        """

        APPLICATION_VND_IBM_KMS_ALLOWED_IP_METADATA_JSON = (
            "application/vnd.ibm.kms.allowed_ip_metadata+json"
        )
        APPLICATION_VND_IBM_KMS_CRN_JSON = "application/vnd.ibm.kms.crn+json"
        APPLICATION_VND_IBM_KMS_ERROR_JSON = "application/vnd.ibm.kms.error+json"
        APPLICATION_VND_IBM_KMS_EVENT_ACKNOWLEDGE_JSON = (
            "application/vnd.ibm.kms.event_acknowledge+json"
        )
        APPLICATION_VND_IBM_KMS_IMPORT_TOKEN_JSON = (
            "application/vnd.ibm.kms.import_token+json"
        )
        APPLICATION_VND_IBM_KMS_KEY_JSON = "application/vnd.ibm.kms.key+json"
        APPLICATION_VND_IBM_KMS_KEY_ACTION_JSON = (
            "application/vnd.ibm.kms.key_action+json"
        )
        APPLICATION_VND_IBM_KMS_ALIAS_JSON = "application/vnd.ibm.kms.alias+json"
        APPLICATION_VND_IBM_KMS_KEY_RING_JSON = "application/vnd.ibm.kms.key_ring+json"
        APPLICATION_VND_IBM_KMS_POLICY_JSON = "application/vnd.ibm.kms.policy+json"
        APPLICATION_VND_IBM_KMS_REGISTRATION_INPUT_JSON = (
            "application/vnd.ibm.kms.registration_input+json"
        )
        APPLICATION_VND_IBM_KMS_REGISTRATION_JSON = (
            "application/vnd.ibm.kms.registration+json"
        )
        APPLICATION_VND_IBM_KMS_RESOURCE_CRN_JSON = (
            "application/vnd.ibm.kms.resource_crn+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_ADAPTER_JSON = (
            "application/vnd.ibm.kms.kmip_adapter+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_CLIENT_CERTIFICATE_JSON = (
            "application/vnd.ibm.kms.kmip_client_certificate+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_OBJECT_JSON = (
            "application/vnd.ibm.kms.kmip_object+json"
        )


class CollectionMetadataOneOf:
    """
    CollectionMetadataOneOf.

    """

    def __init__(
        self,
    ) -> None:
        """
        Initialize a CollectionMetadataOneOf object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(["CollectionMetadataOneOfCollectionMetadata"])
        )
        raise Exception(msg)


class CollectionMetadataWithTotalCount:
    """
    The metadata that describes the resource array.

    :param str collection_type: The type of resources in the resource array.
    :param int collection_total: The number of elements in the resource array.
    :param int total_count: (optional) The total number of elements that match the
          request, disregarding limit and offset.
    """

    def __init__(
        self,
        collection_type: str,
        collection_total: int,
        *,
        total_count: Optional[int] = None,
    ) -> None:
        """
        Initialize a CollectionMetadataWithTotalCount object.

        :param str collection_type: The type of resources in the resource array.
        :param int collection_total: The number of elements in the resource array.
        :param int total_count: (optional) The total number of elements that match
               the request, disregarding limit and offset.
        """
        self.collection_type = collection_type
        self.collection_total = collection_total
        self.total_count = total_count

    @classmethod
    def from_dict(cls, _dict: Dict) -> "CollectionMetadataWithTotalCount":
        """Initialize a CollectionMetadataWithTotalCount object from a json dictionary."""
        args = {}
        if (collection_type := _dict.get("collectionType")) is not None:
            args["collection_type"] = collection_type
        else:
            raise ValueError(
                "Required property 'collectionType' not present in CollectionMetadataWithTotalCount JSON"
            )
        if (collection_total := _dict.get("collectionTotal")) is not None:
            args["collection_total"] = collection_total
        else:
            raise ValueError(
                "Required property 'collectionTotal' not present in CollectionMetadataWithTotalCount JSON"
            )
        if (total_count := _dict.get("totalCount")) is not None:
            args["total_count"] = total_count
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CollectionMetadataWithTotalCount object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "collection_type") and self.collection_type is not None:
            _dict["collectionType"] = self.collection_type
        if hasattr(self, "collection_total") and self.collection_total is not None:
            _dict["collectionTotal"] = self.collection_total
        if hasattr(self, "total_count") and self.total_count is not None:
            _dict["totalCount"] = self.total_count
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CollectionMetadataWithTotalCount object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "CollectionMetadataWithTotalCount") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "CollectionMetadataWithTotalCount") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class CollectionTypeEnum(str, Enum):
        """
        The type of resources in the resource array.
        """

        APPLICATION_VND_IBM_KMS_ALLOWED_IP_METADATA_JSON = (
            "application/vnd.ibm.kms.allowed_ip_metadata+json"
        )
        APPLICATION_VND_IBM_KMS_CRN_JSON = "application/vnd.ibm.kms.crn+json"
        APPLICATION_VND_IBM_KMS_ERROR_JSON = "application/vnd.ibm.kms.error+json"
        APPLICATION_VND_IBM_KMS_EVENT_ACKNOWLEDGE_JSON = (
            "application/vnd.ibm.kms.event_acknowledge+json"
        )
        APPLICATION_VND_IBM_KMS_IMPORT_TOKEN_JSON = (
            "application/vnd.ibm.kms.import_token+json"
        )
        APPLICATION_VND_IBM_KMS_KEY_JSON = "application/vnd.ibm.kms.key+json"
        APPLICATION_VND_IBM_KMS_KEY_ACTION_JSON = (
            "application/vnd.ibm.kms.key_action+json"
        )
        APPLICATION_VND_IBM_KMS_ALIAS_JSON = "application/vnd.ibm.kms.alias+json"
        APPLICATION_VND_IBM_KMS_KEY_RING_JSON = "application/vnd.ibm.kms.key_ring+json"
        APPLICATION_VND_IBM_KMS_POLICY_JSON = "application/vnd.ibm.kms.policy+json"
        APPLICATION_VND_IBM_KMS_REGISTRATION_INPUT_JSON = (
            "application/vnd.ibm.kms.registration_input+json"
        )
        APPLICATION_VND_IBM_KMS_REGISTRATION_JSON = (
            "application/vnd.ibm.kms.registration+json"
        )
        APPLICATION_VND_IBM_KMS_RESOURCE_CRN_JSON = (
            "application/vnd.ibm.kms.resource_crn+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_ADAPTER_JSON = (
            "application/vnd.ibm.kms.kmip_adapter+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_CLIENT_CERTIFICATE_JSON = (
            "application/vnd.ibm.kms.kmip_client_certificate+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_OBJECT_JSON = (
            "application/vnd.ibm.kms.kmip_object+json"
        )


class CreateKMIPAdapterObject:
    """
    CreateKMIPAdapterObject.

    :param str name: (optional) A human-readable name of the KMIP adapter unique
          within the kms instance. If one is not specified, one will be autogenerated of
          the format `kmip_adapter_<random_string>`. To protect your privacy do not use
          personal data, such as your name or location, as a name for your KMIP adapter.
          The name must be alphanumeric and cannot contain spaces or special characters
          other than `-` or `_`. The name cannot be a UUID.
    :param str description: (optional) The optional description of the KMIP adapter.
          The maximum length is 240 characters. To protect your privacy, do not use
          personal data, such as your name or location, as a description for your KMIP
          adapter.
    :param str profile: The profile of KMIP adapter to be created.
    :param KMIPProfileDataBody profile_data: (optional) The data specific to the
          KMIP Adapter profile. This is a required field for profile `native_1.0`.
    """

    def __init__(
        self,
        profile: str,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
        profile_data: Optional["KMIPProfileDataBody"] = None,
    ) -> None:
        """
        Initialize a CreateKMIPAdapterObject object.

        :param str profile: The profile of KMIP adapter to be created.
        :param str name: (optional) A human-readable name of the KMIP adapter
               unique within the kms instance. If one is not specified, one will be
               autogenerated of the format `kmip_adapter_<random_string>`. To protect your
               privacy do not use personal data, such as your name or location, as a name
               for your KMIP adapter. The name must be alphanumeric and cannot contain
               spaces or special characters other than `-` or `_`. The name cannot be a
               UUID.
        :param str description: (optional) The optional description of the KMIP
               adapter. The maximum length is 240 characters. To protect your privacy, do
               not use personal data, such as your name or location, as a description for
               your KMIP adapter.
        :param KMIPProfileDataBody profile_data: (optional) The data specific to
               the KMIP Adapter profile. This is a required field for profile
               `native_1.0`.
        """
        self.name = name
        self.description = description
        self.profile = profile
        self.profile_data = profile_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> "CreateKMIPAdapterObject":
        """Initialize a CreateKMIPAdapterObject object from a json dictionary."""
        args = {}
        if (name := _dict.get("name")) is not None:
            args["name"] = name
        if (description := _dict.get("description")) is not None:
            args["description"] = description
        if (profile := _dict.get("profile")) is not None:
            args["profile"] = profile
        else:
            raise ValueError(
                "Required property 'profile' not present in CreateKMIPAdapterObject JSON"
            )
        if (profile_data := _dict.get("profile_data")) is not None:
            args["profile_data"] = profile_data
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateKMIPAdapterObject object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "name") and self.name is not None:
            _dict["name"] = self.name
        if hasattr(self, "description") and self.description is not None:
            _dict["description"] = self.description
        if hasattr(self, "profile") and self.profile is not None:
            _dict["profile"] = self.profile
        if hasattr(self, "profile_data") and self.profile_data is not None:
            if isinstance(self.profile_data, dict):
                _dict["profile_data"] = self.profile_data
            else:
                _dict["profile_data"] = self.profile_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CreateKMIPAdapterObject object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "CreateKMIPAdapterObject") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "CreateKMIPAdapterObject") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class ProfileEnum(str, Enum):
        """
        The profile of KMIP adapter to be created.
        """

        NATIVE_1_0 = "native_1.0"


class CreateKMIPClientCertificateObject:
    """
    CreateKMIPClientCertificateObject.

    :param str certificate: The client certificate to be associated with the KMIP
          Adapter. It should explicitly have the BEGIN CERTIFICATE and END CERTIFICATE
          tags.
    :param str name: (optional) A human-readable name that uniquely identifies a
          certificate within the given adapter. If one is not specified, one will be
          autogenerated of the format `kmip_cert_<random_string>`. To protect your privacy
          do not use personal data, such as your name or location, as a name for your
          client certificate. The name must be alphanumeric and cannot contain spaces or
          special characters other than `-` or `_`. The name cannot be a UUID.
    """

    def __init__(
        self,
        certificate: str,
        *,
        name: Optional[str] = None,
    ) -> None:
        """
        Initialize a CreateKMIPClientCertificateObject object.

        :param str certificate: The client certificate to be associated with the
               KMIP Adapter. It should explicitly have the BEGIN CERTIFICATE and END
               CERTIFICATE tags.
        :param str name: (optional) A human-readable name that uniquely identifies
               a certificate within the given adapter. If one is not specified, one will
               be autogenerated of the format `kmip_cert_<random_string>`. To protect your
               privacy do not use personal data, such as your name or location, as a name
               for your client certificate. The name must be alphanumeric and cannot
               contain spaces or special characters other than `-` or `_`. The name cannot
               be a UUID.
        """
        self.certificate = certificate
        self.name = name

    @classmethod
    def from_dict(cls, _dict: Dict) -> "CreateKMIPClientCertificateObject":
        """Initialize a CreateKMIPClientCertificateObject object from a json dictionary."""
        args = {}
        if (certificate := _dict.get("certificate")) is not None:
            args["certificate"] = certificate
        else:
            raise ValueError(
                "Required property 'certificate' not present in CreateKMIPClientCertificateObject JSON"
            )
        if (name := _dict.get("name")) is not None:
            args["name"] = name
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateKMIPClientCertificateObject object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "certificate") and self.certificate is not None:
            _dict["certificate"] = self.certificate
        if hasattr(self, "name") and self.name is not None:
            _dict["name"] = self.name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CreateKMIPClientCertificateObject object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "CreateKMIPClientCertificateObject") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "CreateKMIPClientCertificateObject") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DeleteKey:
    """
    The base schema for deleting keys.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param List[KeyWithPayload] resources: A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List["KeyWithPayload"],
    ) -> None:
        """
        Initialize a DeleteKey object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[KeyWithPayload] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "DeleteKey":
        """Initialize a DeleteKey object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in DeleteKey JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [KeyWithPayload.from_dict(v) for v in resources]
        else:
            raise ValueError(
                "Required property 'resources' not present in DeleteKey JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DeleteKey object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DeleteKey object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "DeleteKey") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "DeleteKey") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DualAuthDeleteProperties:
    """
    User defined metadata that is associated with the `dualAuthDelete` instance policy
    type.

    :param bool enabled: If set to `true`, Key Protect enables a dual authorization
          deletion policy for your service instance. By default, Key Protect requires only
          one authorization to delete a key. After you enable a dual authorization policy,
          any new key that you create or add to the instance will require an authorization
          from two users to delete keys.
          **Note:** This change does not affect existing keys in your instance.
    """

    def __init__(
        self,
        enabled: bool,
    ) -> None:
        """
        Initialize a DualAuthDeleteProperties object.

        :param bool enabled: If set to `true`, Key Protect enables a dual
               authorization deletion policy for your service instance. By default, Key
               Protect requires only one authorization to delete a key. After you enable a
               dual authorization policy, any new key that you create or add to the
               instance will require an authorization from two users to delete keys.
               **Note:** This change does not affect existing keys in your instance.
        """
        self.enabled = enabled

    @classmethod
    def from_dict(cls, _dict: Dict) -> "DualAuthDeleteProperties":
        """Initialize a DualAuthDeleteProperties object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            raise ValueError(
                "Required property 'enabled' not present in DualAuthDeleteProperties JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DualAuthDeleteProperties object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DualAuthDeleteProperties object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "DualAuthDeleteProperties") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "DualAuthDeleteProperties") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DualAuthKeyMetadata:
    """
    Metadata that indicates the status of a dual authorization policy on the key.

    :param bool enabled: The status of a dual authorization policy on the key. If
          `true`, dual authorization is required to delete the key. If `false`, no prior
          authorization is required to delete the key.
    :param bool key_set_for_deletion: (optional) Indicates if a delete authorization
          has been issued for a key. If `true`, an authorization to delete this key has
          been issued by the first user, and a second user with a Manager access policy
          can safely delete the key. If the `enabled` property is `false`, this field is
          omitted in the response body.
    :param datetime auth_expiration: (optional) The date that an authorization for
          deletion expires for the key. If this date has passed, the authorization is no
          longer valid. If the `enabled` or `keySetForDeletion` properties are `false`,
          this field is omitted in the response body.
    """

    def __init__(
        self,
        enabled: bool,
        *,
        key_set_for_deletion: Optional[bool] = None,
        auth_expiration: Optional[datetime] = None,
    ) -> None:
        """
        Initialize a DualAuthKeyMetadata object.

        :param bool enabled: The status of a dual authorization policy on the key.
               If `true`, dual authorization is required to delete the key. If `false`, no
               prior authorization is required to delete the key.
        :param bool key_set_for_deletion: (optional) Indicates if a delete
               authorization has been issued for a key. If `true`, an authorization to
               delete this key has been issued by the first user, and a second user with a
               Manager access policy can safely delete the key. If the `enabled` property
               is `false`, this field is omitted in the response body.
        """
        self.enabled = enabled
        self.key_set_for_deletion = key_set_for_deletion
        self.auth_expiration = auth_expiration

    @classmethod
    def from_dict(cls, _dict: Dict) -> "DualAuthKeyMetadata":
        """Initialize a DualAuthKeyMetadata object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            raise ValueError(
                "Required property 'enabled' not present in DualAuthKeyMetadata JSON"
            )
        if (key_set_for_deletion := _dict.get("keySetForDeletion")) is not None:
            args["key_set_for_deletion"] = key_set_for_deletion
        if (auth_expiration := _dict.get("authExpiration")) is not None:
            args["auth_expiration"] = string_to_datetime(auth_expiration)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DualAuthKeyMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        if (
            hasattr(self, "key_set_for_deletion")
            and self.key_set_for_deletion is not None
        ):
            _dict["keySetForDeletion"] = self.key_set_for_deletion
        if (
            hasattr(self, "auth_expiration")
            and getattr(self, "auth_expiration") is not None
        ):
            _dict["authExpiration"] = datetime_to_string(
                getattr(self, "auth_expiration")
            )
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DualAuthKeyMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "DualAuthKeyMetadata") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "DualAuthKeyMetadata") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetImportToken:
    """
    The base schema for retrieving an import token.

    :param float expiration: (optional) The time in seconds from the creation of an
          import token that determines how long its associated public key remains valid.
          The minimum value is `300` seconds (5 minutes), and the maximum value is `86400`
          (24 hours). The default value is `600` (10 minutes).
    :param float max_allowed_retrievals: (optional) The number of times that an
          import token can be retrieved within its expiration time before it is no longer
          accessible.
    :param datetime creation_date: (optional) The date the import token was created.
          The date format follows RFC 3339.
    :param datetime expiration_date: (optional) The date the import token expires.
          The date format follows RFC 3339.
    :param float remaining_retrievals: (optional) The number of retrievals that are
          available for the import token before it is no longer accessible.
    :param bytes payload: (optional) The public encryption key that you can use to
          encrypt key material before you import it into the service. This value is a
          PEM-encoded public key in PKIX format. Because PEM encoding is a binary format,
          the value is base64 encoded.
    :param bytes nonce: (optional) The nonce value that is used to verify a key
          import request. Encrypt and provide the encrypted nonce value when you use `POST
          /keys` to securely import a key to the service.
    """

    def __init__(
        self,
        *,
        expiration: Optional[float] = None,
        max_allowed_retrievals: Optional[float] = None,
        creation_date: Optional[datetime] = None,
        expiration_date: Optional[datetime] = None,
        remaining_retrievals: Optional[float] = None,
        payload: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> None:
        """
        Initialize a GetImportToken object.

        :param float expiration: (optional) The time in seconds from the creation
               of an import token that determines how long its associated public key
               remains valid. The minimum value is `300` seconds (5 minutes), and the
               maximum value is `86400` (24 hours). The default value is `600` (10
               minutes).
        :param float max_allowed_retrievals: (optional) The number of times that an
               import token can be retrieved within its expiration time before it is no
               longer accessible.
        """
        self.expiration = expiration
        self.max_allowed_retrievals = max_allowed_retrievals
        self.creation_date = creation_date
        self.expiration_date = expiration_date
        self.remaining_retrievals = remaining_retrievals
        self.payload = payload
        self.nonce = nonce

    @classmethod
    def from_dict(cls, _dict: Dict) -> "GetImportToken":
        """Initialize a GetImportToken object from a json dictionary."""
        args = {}
        if (expiration := _dict.get("expiration")) is not None:
            args["expiration"] = expiration
        if (max_allowed_retrievals := _dict.get("maxAllowedRetrievals")) is not None:
            args["max_allowed_retrievals"] = max_allowed_retrievals
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (expiration_date := _dict.get("expirationDate")) is not None:
            args["expiration_date"] = string_to_datetime(expiration_date)
        if (remaining_retrievals := _dict.get("remainingRetrievals")) is not None:
            args["remaining_retrievals"] = remaining_retrievals
        if (payload := _dict.get("payload")) is not None:
            args["payload"] = base64.b64decode(payload)
        if (nonce := _dict.get("nonce")) is not None:
            args["nonce"] = base64.b64decode(nonce)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetImportToken object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "expiration") and self.expiration is not None:
            _dict["expiration"] = self.expiration
        if (
            hasattr(self, "max_allowed_retrievals")
            and self.max_allowed_retrievals is not None
        ):
            _dict["maxAllowedRetrievals"] = self.max_allowed_retrievals
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        if (
            hasattr(self, "expiration_date")
            and getattr(self, "expiration_date") is not None
        ):
            _dict["expirationDate"] = datetime_to_string(
                getattr(self, "expiration_date")
            )
        if (
            hasattr(self, "remaining_retrievals")
            and getattr(self, "remaining_retrievals") is not None
        ):
            _dict["remainingRetrievals"] = getattr(self, "remaining_retrievals")
        if hasattr(self, "payload") and getattr(self, "payload") is not None:
            _dict["payload"] = str(base64.b64encode(getattr(self, "payload")), "utf-8")
        if hasattr(self, "nonce") and getattr(self, "nonce") is not None:
            _dict["nonce"] = str(base64.b64encode(getattr(self, "nonce")), "utf-8")
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetImportToken object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "GetImportToken") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "GetImportToken") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePoliciesOneOf:
    """
    GetInstancePoliciesOneOf.

    """

    def __init__(
        self,
    ) -> None:
        """
        Initialize a GetInstancePoliciesOneOf object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(
                [
                    "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork",
                    "GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete",
                    "GetInstancePoliciesOneOfGetInstancePolicyAllowedIP",
                    "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess",
                    "GetInstancePoliciesOneOfGetInstancePolicyMetrics",
                    "GetInstancePoliciesOneOfGetInstancePolicyRotation",
                    "GetInstancePoliciesOneOfGetMultipleInstancePolicies",
                ]
            )
        )
        raise Exception(msg)


class GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem:
    """
    GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem.

    :param datetime creation_date: (optional) The date the policy was created. The
          date format follows RFC 3339.
    :param str created_by: (optional) The unique identifier for the resource that
          created the policy.
    :param str updated_by: (optional) The unique identifier for the resource that
          updated the policy.
    :param datetime last_updated: (optional) Updates when the policy is replaced or
          modified. The date format follows RFC 3339.
    :param str policy_type: The type of policy to be retrieved.
    :param
          GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData
          policy_data: User defined metadata that is associated with the `allowedNetwork`
          instance policy type.
    """

    def __init__(
        self,
        policy_type: str,
        policy_data: "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData",
        *,
        creation_date: Optional[datetime] = None,
        created_by: Optional[str] = None,
        updated_by: Optional[str] = None,
        last_updated: Optional[datetime] = None,
    ) -> None:
        """
        Initialize a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem object.

        :param str policy_type: The type of policy to be retrieved.
        :param
               GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData
               policy_data: User defined metadata that is associated with the
               `allowedNetwork` instance policy type.
        """
        self.creation_date = creation_date
        self.created_by = created_by
        self.updated_by = updated_by
        self.last_updated = last_updated
        self.policy_type = policy_type
        self.policy_data = policy_data

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem":
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem object from a json dictionary."""
        args = {}
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (created_by := _dict.get("createdBy")) is not None:
            args["created_by"] = created_by
        if (updated_by := _dict.get("updatedBy")) is not None:
            args["updated_by"] = updated_by
        if (last_updated := _dict.get("lastUpdated")) is not None:
            args["last_updated"] = string_to_datetime(last_updated)
        if (policy_type := _dict.get("policy_type")) is not None:
            args["policy_type"] = policy_type
        else:
            raise ValueError(
                "Required property 'policy_type' not present in GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem JSON"
            )
        if (policy_data := _dict.get("policy_data")) is not None:
            args["policy_data"] = (
                GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData.from_dict(
                    policy_data
                )
            )
        else:
            raise ValueError(
                "Required property 'policy_data' not present in GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        if hasattr(self, "created_by") and getattr(self, "created_by") is not None:
            _dict["createdBy"] = getattr(self, "created_by")
        if hasattr(self, "updated_by") and getattr(self, "updated_by") is not None:
            _dict["updatedBy"] = getattr(self, "updated_by")
        if hasattr(self, "last_updated") and getattr(self, "last_updated") is not None:
            _dict["lastUpdated"] = datetime_to_string(getattr(self, "last_updated"))
        if hasattr(self, "policy_type") and self.policy_type is not None:
            _dict["policy_type"] = self.policy_type
        if hasattr(self, "policy_data") and self.policy_data is not None:
            if isinstance(self.policy_data, dict):
                _dict["policy_data"] = self.policy_data
            else:
                _dict["policy_data"] = self.policy_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self,
        other: "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem",
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self,
        other: "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem",
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData:
    """
    User defined metadata that is associated with the `allowedNetwork` instance policy
    type.

    :param bool enabled: If set to `true`, Key Protect enables the specified policy
          for your service instance. If set to `false`, Key Protect disables the specified
          policy for your service instance, and the policy will no longer affect Key
          Protect actions.
          **Note:** If a policy with attributes is disabled, all attributes are reset and
          are not retained.
    :param
          GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes
          attributes: (optional) Data associated with the policy type `allowed_network`.
    """

    def __init__(
        self,
        enabled: bool,
        *,
        attributes: Optional[
            "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes"
        ] = None,
    ) -> None:
        """
        Initialize a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData object.

        :param bool enabled: If set to `true`, Key Protect enables the specified
               policy for your service instance. If set to `false`, Key Protect disables
               the specified policy for your service instance, and the policy will no
               longer affect Key Protect actions.
               **Note:** If a policy with attributes is disabled, all attributes are reset
               and are not retained.
        :param
               GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes
               attributes: (optional) Data associated with the policy type
               `allowed_network`.
        """
        self.enabled = enabled
        self.attributes = attributes

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> (
        "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData"
    ):
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            args["enabled"] = None
        if (attributes := _dict.get("attributes")) is not None:
            args["attributes"] = (
                GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes.from_dict(
                    attributes
                )
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        if hasattr(self, "attributes") and self.attributes is not None:
            if isinstance(self.attributes, dict):
                _dict["attributes"] = self.attributes
            else:
                _dict["attributes"] = self.attributes.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self,
        other: "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData",
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self,
        other: "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData",
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes:
    """
    Data associated with the policy type `allowed_network`.

    :param str allowed_network: If set to `public-and-private`, Key Protect allows
          the instance to be accessible through public and private endpoints. If set to
          `private-only`, Key Protect restricts the instance to only be accessible through
          a private endpoint.
    """

    def __init__(
        self,
        allowed_network: str,
    ) -> None:
        """
        Initialize a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes object.

        :param str allowed_network: If set to `public-and-private`, Key Protect
               allows the instance to be accessible through public and private endpoints.
               If set to `private-only`, Key Protect restricts the instance to only be
               accessible through a private endpoint.
        """
        self.allowed_network = allowed_network

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes":
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes object from a json dictionary."""
        args = {}
        if (allowed_network := _dict.get("allowed_network")) is not None:
            args["allowed_network"] = allowed_network
        else:
            args["allowed_network"] = None
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "allowed_network") and self.allowed_network is not None:
            _dict["allowed_network"] = self.allowed_network
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self,
        other: "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes",
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self,
        other: "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes",
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class AllowedNetworkEnum(str, Enum):
        """
        If set to `public-and-private`, Key Protect allows the instance to be accessible
        through public and private endpoints. If set to `private-only`, Key Protect
        restricts the instance to only be accessible through a private endpoint.
        """

        PUBLIC_AND_PRIVATE = "public-and-private"
        PRIVATE_ONLY = "private-only"


class GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem:
    """
    GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem.

    :param datetime creation_date: (optional) The date the policy was created. The
          date format follows RFC 3339.
    :param str created_by: (optional) The unique identifier for the resource that
          created the policy.
    :param str updated_by: (optional) The unique identifier for the resource that
          updated the policy.
    :param datetime last_updated: (optional) Updates when the policy is replaced or
          modified. The date format follows RFC 3339.
    :param str policy_type: The type of policy to be retrieved.
    :param
          GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData
          policy_data: User defined metadata that is associated with the
          `keyCreateImportAccess` instance policy type.
    """

    def __init__(
        self,
        policy_type: str,
        policy_data: "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData",
        *,
        creation_date: Optional[datetime] = None,
        created_by: Optional[str] = None,
        updated_by: Optional[str] = None,
        last_updated: Optional[datetime] = None,
    ) -> None:
        """
        Initialize a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem object.

        :param str policy_type: The type of policy to be retrieved.
        :param
               GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData
               policy_data: User defined metadata that is associated with the
               `keyCreateImportAccess` instance policy type.
        """
        self.creation_date = creation_date
        self.created_by = created_by
        self.updated_by = updated_by
        self.last_updated = last_updated
        self.policy_type = policy_type
        self.policy_data = policy_data

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem":
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem object from a json dictionary."""
        args = {}
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (created_by := _dict.get("createdBy")) is not None:
            args["created_by"] = created_by
        if (updated_by := _dict.get("updatedBy")) is not None:
            args["updated_by"] = updated_by
        if (last_updated := _dict.get("lastUpdated")) is not None:
            args["last_updated"] = string_to_datetime(last_updated)
        if (policy_type := _dict.get("policy_type")) is not None:
            args["policy_type"] = policy_type
        else:
            raise ValueError(
                "Required property 'policy_type' not present in GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem JSON"
            )
        if (policy_data := _dict.get("policy_data")) is not None:
            args["policy_data"] = (
                GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData.from_dict(
                    policy_data
                )
            )
        else:
            raise ValueError(
                "Required property 'policy_data' not present in GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        if hasattr(self, "created_by") and getattr(self, "created_by") is not None:
            _dict["createdBy"] = getattr(self, "created_by")
        if hasattr(self, "updated_by") and getattr(self, "updated_by") is not None:
            _dict["updatedBy"] = getattr(self, "updated_by")
        if hasattr(self, "last_updated") and getattr(self, "last_updated") is not None:
            _dict["lastUpdated"] = datetime_to_string(getattr(self, "last_updated"))
        if hasattr(self, "policy_type") and self.policy_type is not None:
            _dict["policy_type"] = self.policy_type
        if hasattr(self, "policy_data") and self.policy_data is not None:
            if isinstance(self.policy_data, dict):
                _dict["policy_data"] = self.policy_data
            else:
                _dict["policy_data"] = self.policy_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self,
        other: "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem",
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self,
        other: "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem",
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData:
    """
    User defined metadata that is associated with the `keyCreateImportAccess` instance
    policy type.

    :param bool enabled: If set to `true`, Key Protect enables the specified policy
          for your service instance. If set to `false`, Key Protect disables the specified
          policy for your service instance, and the policy will no longer affect Key
          Protect actions.
          **Note:** If a policy with attributes is disabled, all attributes are reset and
          are not retained.
    :param
          GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes
          attributes: (optional) Data associated with the policy type
          `keyCreateImportAccess`.
    """

    def __init__(
        self,
        enabled: bool,
        *,
        attributes: Optional[
            "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes"
        ] = None,
    ) -> None:
        """
        Initialize a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData object.

        :param bool enabled: If set to `true`, Key Protect enables the specified
               policy for your service instance. If set to `false`, Key Protect disables
               the specified policy for your service instance, and the policy will no
               longer affect Key Protect actions.
               **Note:** If a policy with attributes is disabled, all attributes are reset
               and are not retained.
        :param
               GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes
               attributes: (optional) Data associated with the policy type
               `keyCreateImportAccess`.
        """
        self.enabled = enabled
        self.attributes = attributes

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData":
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            args["enabled"] = None
        if (attributes := _dict.get("attributes")) is not None:
            args["attributes"] = (
                GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes.from_dict(
                    attributes
                )
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        if hasattr(self, "attributes") and self.attributes is not None:
            if isinstance(self.attributes, dict):
                _dict["attributes"] = self.attributes
            else:
                _dict["attributes"] = self.attributes.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self,
        other: "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData",
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self,
        other: "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData",
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes:
    """
    Data associated with the policy type `keyCreateImportAccess`.

    :param bool create_root_key: If set to `false`, the service prevents you or any
          authorized users from using Key Protect to create root keys in the specified
          service instance. If set to `true`, Key Protect allows you or any authorized
          users to create root keys in the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool create_standard_key: If set to `false`, the service prevents you or
          any authorized users from using Key Protect to create standard keys in the
          specified service instance. If set to `true`, Key Protect allows you or any
          authorized users to create standard keys in the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool import_root_key: If set to `false`, the service prevents you or any
          authorized users from importing root keys into the specified service instance.
          If set to `true`, Key Protect allows you or any authorized users to import root
          keys into the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool import_standard_key: If set to `false`, the service prevents you or
          any authorized users from importing standard keys into the specified service
          instance. If set to `true`, Key Protect allows you or any authorized users to
          import standard keys into the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool enforce_token: If set to `true`, the service prevents you or any
          authorized users from importing key material into the specified service instance
          without using an import token. If set to `false`, Key Protect allows you or any
          authorized users to import key material into the instance without the use of an
          import token.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`false`).
    """

    def __init__(
        self,
        create_root_key: bool,
        create_standard_key: bool,
        import_root_key: bool,
        import_standard_key: bool,
        enforce_token: bool,
    ) -> None:
        """
        Initialize a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes object.

        :param bool create_root_key: If set to `false`, the service prevents you or
               any authorized users from using Key Protect to create root keys in the
               specified service instance. If set to `true`, Key Protect allows you or any
               authorized users to create root keys in the instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool create_standard_key: If set to `false`, the service prevents
               you or any authorized users from using Key Protect to create standard keys
               in the specified service instance. If set to `true`, Key Protect allows you
               or any authorized users to create standard keys in the instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool import_root_key: If set to `false`, the service prevents you or
               any authorized users from importing root keys into the specified service
               instance. If set to `true`, Key Protect allows you or any authorized users
               to import root keys into the instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool import_standard_key: If set to `false`, the service prevents
               you or any authorized users from importing standard keys into the specified
               service instance. If set to `true`, Key Protect allows you or any
               authorized users to import standard keys into the instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool enforce_token: If set to `true`, the service prevents you or
               any authorized users from importing key material into the specified service
               instance without using an import token. If set to `false`, Key Protect
               allows you or any authorized users to import key material into the instance
               without the use of an import token.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`false`).
        """
        self.create_root_key = create_root_key
        self.create_standard_key = create_standard_key
        self.import_root_key = import_root_key
        self.import_standard_key = import_standard_key
        self.enforce_token = enforce_token

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes":
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes object from a json dictionary."""
        args = {}
        if (create_root_key := _dict.get("create_root_key")) is not None:
            args["create_root_key"] = create_root_key
        else:
            args["create_root_key"] = None
        if (create_standard_key := _dict.get("create_standard_key")) is not None:
            args["create_standard_key"] = create_standard_key
        else:
            args["create_standard_key"] = None
        if (import_root_key := _dict.get("import_root_key")) is not None:
            args["import_root_key"] = import_root_key
        else:
            args["import_root_key"] = None
        if (import_standard_key := _dict.get("import_standard_key")) is not None:
            args["import_standard_key"] = import_standard_key
        else:
            args["import_standard_key"] = None
        if (enforce_token := _dict.get("enforce_token")) is not None:
            args["enforce_token"] = enforce_token
        else:
            args["enforce_token"] = None
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "create_root_key") and self.create_root_key is not None:
            _dict["create_root_key"] = self.create_root_key
        if (
            hasattr(self, "create_standard_key")
            and self.create_standard_key is not None
        ):
            _dict["create_standard_key"] = self.create_standard_key
        if hasattr(self, "import_root_key") and self.import_root_key is not None:
            _dict["import_root_key"] = self.import_root_key
        if (
            hasattr(self, "import_standard_key")
            and self.import_standard_key is not None
        ):
            _dict["import_standard_key"] = self.import_standard_key
        if hasattr(self, "enforce_token") and self.enforce_token is not None:
            _dict["enforce_token"] = self.enforce_token
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self,
        other: "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes",
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self,
        other: "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes",
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePolicyAllowedIPResourcesItem:
    """
    GetInstancePolicyAllowedIPResourcesItem.

    :param datetime creation_date: (optional) The date the policy was created. The
          date format follows RFC 3339.
    :param str created_by: (optional) The unique identifier for the resource that
          created the policy.
    :param str updated_by: (optional) The unique identifier for the resource that
          updated the policy.
    :param datetime last_updated: (optional) Updates when the policy is replaced or
          modified. The date format follows RFC 3339.
    :param str policy_type: The type of policy to be retrieved.
    :param GetInstancePolicyAllowedIPResourcesItemPolicyData policy_data: User
          defined metadata that is associated with the `allowedIP` instance policy type.
    """

    def __init__(
        self,
        policy_type: str,
        policy_data: "GetInstancePolicyAllowedIPResourcesItemPolicyData",
        *,
        creation_date: Optional[datetime] = None,
        created_by: Optional[str] = None,
        updated_by: Optional[str] = None,
        last_updated: Optional[datetime] = None,
    ) -> None:
        """
        Initialize a GetInstancePolicyAllowedIPResourcesItem object.

        :param str policy_type: The type of policy to be retrieved.
        :param GetInstancePolicyAllowedIPResourcesItemPolicyData policy_data: User
               defined metadata that is associated with the `allowedIP` instance policy
               type.
        """
        self.creation_date = creation_date
        self.created_by = created_by
        self.updated_by = updated_by
        self.last_updated = last_updated
        self.policy_type = policy_type
        self.policy_data = policy_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> "GetInstancePolicyAllowedIPResourcesItem":
        """Initialize a GetInstancePolicyAllowedIPResourcesItem object from a json dictionary."""
        args = {}
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (created_by := _dict.get("createdBy")) is not None:
            args["created_by"] = created_by
        if (updated_by := _dict.get("updatedBy")) is not None:
            args["updated_by"] = updated_by
        if (last_updated := _dict.get("lastUpdated")) is not None:
            args["last_updated"] = string_to_datetime(last_updated)
        if (policy_type := _dict.get("policy_type")) is not None:
            args["policy_type"] = policy_type
        else:
            raise ValueError(
                "Required property 'policy_type' not present in GetInstancePolicyAllowedIPResourcesItem JSON"
            )
        if (policy_data := _dict.get("policy_data")) is not None:
            args["policy_data"] = (
                GetInstancePolicyAllowedIPResourcesItemPolicyData.from_dict(policy_data)
            )
        else:
            raise ValueError(
                "Required property 'policy_data' not present in GetInstancePolicyAllowedIPResourcesItem JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePolicyAllowedIPResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        if hasattr(self, "created_by") and getattr(self, "created_by") is not None:
            _dict["createdBy"] = getattr(self, "created_by")
        if hasattr(self, "updated_by") and getattr(self, "updated_by") is not None:
            _dict["updatedBy"] = getattr(self, "updated_by")
        if hasattr(self, "last_updated") and getattr(self, "last_updated") is not None:
            _dict["lastUpdated"] = datetime_to_string(getattr(self, "last_updated"))
        if hasattr(self, "policy_type") and self.policy_type is not None:
            _dict["policy_type"] = self.policy_type
        if hasattr(self, "policy_data") and self.policy_data is not None:
            if isinstance(self.policy_data, dict):
                _dict["policy_data"] = self.policy_data
            else:
                _dict["policy_data"] = self.policy_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePolicyAllowedIPResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "GetInstancePolicyAllowedIPResourcesItem") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "GetInstancePolicyAllowedIPResourcesItem") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePolicyAllowedIPResourcesItemPolicyData:
    """
    User defined metadata that is associated with the `allowedIP` instance policy type.

    :param bool enabled: If set to `true`, Key Protect enables the specified policy
          for your service instance. If set to `false`, Key Protect disables the specified
          policy for your service instance, and the policy will no longer affect Key
          Protect actions.
          **Note:** If a policy with attributes is disabled, all attributes are reset and
          are not retained.
    :param GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes attributes:
          (optional) Data associated with the policy type `allowedIP`.
    """

    def __init__(
        self,
        enabled: bool,
        *,
        attributes: Optional[
            "GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes"
        ] = None,
    ) -> None:
        """
        Initialize a GetInstancePolicyAllowedIPResourcesItemPolicyData object.

        :param bool enabled: If set to `true`, Key Protect enables the specified
               policy for your service instance. If set to `false`, Key Protect disables
               the specified policy for your service instance, and the policy will no
               longer affect Key Protect actions.
               **Note:** If a policy with attributes is disabled, all attributes are reset
               and are not retained.
        :param GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes
               attributes: (optional) Data associated with the policy type `allowedIP`.
        """
        self.enabled = enabled
        self.attributes = attributes

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePolicyAllowedIPResourcesItemPolicyData":
        """Initialize a GetInstancePolicyAllowedIPResourcesItemPolicyData object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            args["enabled"] = None
        if (attributes := _dict.get("attributes")) is not None:
            args["attributes"] = (
                GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes.from_dict(
                    attributes
                )
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePolicyAllowedIPResourcesItemPolicyData object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        if hasattr(self, "attributes") and self.attributes is not None:
            if isinstance(self.attributes, dict):
                _dict["attributes"] = self.attributes
            else:
                _dict["attributes"] = self.attributes.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePolicyAllowedIPResourcesItemPolicyData object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "GetInstancePolicyAllowedIPResourcesItemPolicyData"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "GetInstancePolicyAllowedIPResourcesItemPolicyData"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes:
    """
    Data associated with the policy type `allowedIP`.

    :param List[str] allowed_ip: (optional) A string array of IPv4 or IPv6 CIDR
          notated subnets that are authorized to interact with the instance. If both
          `allowedNetwork` and `allowedIP` policies are set, only traffic aligning with
          both the `allowed_network` allowed network policy attribute and the `allowed_ip`
          allowed IP policy attribute will be allowed. IPv4 and iIP6 addresses are
          accepted for public endpoints. Only the IPv4 private network gateway addresses
          from the array will be authorized to access your instance via private endpoint.
          **Important:** Once set, accessing your instance may require additional steps.
          For more information, see [Accessing an instance via public
          endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-public-endpoint)
          and [Accessing an instance via private
          endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-private-endpoint)
          for more details.
          **Note:** An allowed IP policy does not affect requests from other IBM Cloud
          services.
    """

    def __init__(
        self,
        *,
        allowed_ip: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes object.

        :param List[str] allowed_ip: (optional) A string array of IPv4 or IPv6 CIDR
               notated subnets that are authorized to interact with the instance. If both
               `allowedNetwork` and `allowedIP` policies are set, only traffic aligning
               with both the `allowed_network` allowed network policy attribute and the
               `allowed_ip` allowed IP policy attribute will be allowed. IPv4 and iIP6
               addresses are accepted for public endpoints. Only the IPv4 private network
               gateway addresses from the array will be authorized to access your instance
               via private endpoint.
               **Important:** Once set, accessing your instance may require additional
               steps. For more information, see [Accessing an instance via public
               endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-public-endpoint)
               and [Accessing an instance via private
               endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-private-endpoint)
               for more details.
               **Note:** An allowed IP policy does not affect requests from other IBM
               Cloud services.
        """
        self.allowed_ip = allowed_ip

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes":
        """Initialize a GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes object from a json dictionary."""
        args = {}
        if (allowed_ip := _dict.get("allowed_ip")) is not None:
            args["allowed_ip"] = allowed_ip
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "allowed_ip") and self.allowed_ip is not None:
            _dict["allowed_ip"] = self.allowed_ip
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePolicyDualAuthDeleteResourcesItem:
    """
    GetInstancePolicyDualAuthDeleteResourcesItem.

    :param datetime creation_date: (optional) The date the policy was created. The
          date format follows RFC 3339.
    :param str created_by: (optional) The unique identifier for the resource that
          created the policy.
    :param str updated_by: (optional) The unique identifier for the resource that
          updated the policy.
    :param datetime last_updated: (optional) Updates when the policy is replaced or
          modified. The date format follows RFC 3339.
    :param str policy_type: The type of policy to be retrieved.
    :param DualAuthDeleteProperties policy_data: User defined metadata that is
          associated with the `dualAuthDelete` instance policy type.
    """

    def __init__(
        self,
        policy_type: str,
        policy_data: "DualAuthDeleteProperties",
        *,
        creation_date: Optional[datetime] = None,
        created_by: Optional[str] = None,
        updated_by: Optional[str] = None,
        last_updated: Optional[datetime] = None,
    ) -> None:
        """
        Initialize a GetInstancePolicyDualAuthDeleteResourcesItem object.

        :param str policy_type: The type of policy to be retrieved.
        :param DualAuthDeleteProperties policy_data: User defined metadata that is
               associated with the `dualAuthDelete` instance policy type.
        """
        self.creation_date = creation_date
        self.created_by = created_by
        self.updated_by = updated_by
        self.last_updated = last_updated
        self.policy_type = policy_type
        self.policy_data = policy_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> "GetInstancePolicyDualAuthDeleteResourcesItem":
        """Initialize a GetInstancePolicyDualAuthDeleteResourcesItem object from a json dictionary."""
        args = {}
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (created_by := _dict.get("createdBy")) is not None:
            args["created_by"] = created_by
        if (updated_by := _dict.get("updatedBy")) is not None:
            args["updated_by"] = updated_by
        if (last_updated := _dict.get("lastUpdated")) is not None:
            args["last_updated"] = string_to_datetime(last_updated)
        if (policy_type := _dict.get("policy_type")) is not None:
            args["policy_type"] = policy_type
        else:
            raise ValueError(
                "Required property 'policy_type' not present in GetInstancePolicyDualAuthDeleteResourcesItem JSON"
            )
        if (policy_data := _dict.get("policy_data")) is not None:
            args["policy_data"] = DualAuthDeleteProperties.from_dict(policy_data)
        else:
            raise ValueError(
                "Required property 'policy_data' not present in GetInstancePolicyDualAuthDeleteResourcesItem JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePolicyDualAuthDeleteResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        if hasattr(self, "created_by") and getattr(self, "created_by") is not None:
            _dict["createdBy"] = getattr(self, "created_by")
        if hasattr(self, "updated_by") and getattr(self, "updated_by") is not None:
            _dict["updatedBy"] = getattr(self, "updated_by")
        if hasattr(self, "last_updated") and getattr(self, "last_updated") is not None:
            _dict["lastUpdated"] = datetime_to_string(getattr(self, "last_updated"))
        if hasattr(self, "policy_type") and self.policy_type is not None:
            _dict["policy_type"] = self.policy_type
        if hasattr(self, "policy_data") and self.policy_data is not None:
            if isinstance(self.policy_data, dict):
                _dict["policy_data"] = self.policy_data
            else:
                _dict["policy_data"] = self.policy_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePolicyDualAuthDeleteResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "GetInstancePolicyDualAuthDeleteResourcesItem") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "GetInstancePolicyDualAuthDeleteResourcesItem") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePolicyMetricsResourcesItem:
    """
    GetInstancePolicyMetricsResourcesItem.

    :param datetime creation_date: (optional) The date the policy was created. The
          date format follows RFC 3339.
    :param str created_by: (optional) The unique identifier for the resource that
          created the policy.
    :param str updated_by: (optional) The unique identifier for the resource that
          updated the policy.
    :param datetime last_updated: (optional) Updates when the policy is replaced or
          modified. The date format follows RFC 3339.
    :param str policy_type: The type of policy to be retrieved.
    :param MetricsProperties policy_data: User defined metadata that is associated
          with the `metrics` instance policy type.
    """

    def __init__(
        self,
        policy_type: str,
        policy_data: "MetricsProperties",
        *,
        creation_date: Optional[datetime] = None,
        created_by: Optional[str] = None,
        updated_by: Optional[str] = None,
        last_updated: Optional[datetime] = None,
    ) -> None:
        """
        Initialize a GetInstancePolicyMetricsResourcesItem object.

        :param str policy_type: The type of policy to be retrieved.
        :param MetricsProperties policy_data: User defined metadata that is
               associated with the `metrics` instance policy type.
        """
        self.creation_date = creation_date
        self.created_by = created_by
        self.updated_by = updated_by
        self.last_updated = last_updated
        self.policy_type = policy_type
        self.policy_data = policy_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> "GetInstancePolicyMetricsResourcesItem":
        """Initialize a GetInstancePolicyMetricsResourcesItem object from a json dictionary."""
        args = {}
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (created_by := _dict.get("createdBy")) is not None:
            args["created_by"] = created_by
        if (updated_by := _dict.get("updatedBy")) is not None:
            args["updated_by"] = updated_by
        if (last_updated := _dict.get("lastUpdated")) is not None:
            args["last_updated"] = string_to_datetime(last_updated)
        if (policy_type := _dict.get("policy_type")) is not None:
            args["policy_type"] = policy_type
        else:
            raise ValueError(
                "Required property 'policy_type' not present in GetInstancePolicyMetricsResourcesItem JSON"
            )
        if (policy_data := _dict.get("policy_data")) is not None:
            args["policy_data"] = MetricsProperties.from_dict(policy_data)
        else:
            raise ValueError(
                "Required property 'policy_data' not present in GetInstancePolicyMetricsResourcesItem JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePolicyMetricsResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        if hasattr(self, "created_by") and getattr(self, "created_by") is not None:
            _dict["createdBy"] = getattr(self, "created_by")
        if hasattr(self, "updated_by") and getattr(self, "updated_by") is not None:
            _dict["updatedBy"] = getattr(self, "updated_by")
        if hasattr(self, "last_updated") and getattr(self, "last_updated") is not None:
            _dict["lastUpdated"] = datetime_to_string(getattr(self, "last_updated"))
        if hasattr(self, "policy_type") and self.policy_type is not None:
            _dict["policy_type"] = self.policy_type
        if hasattr(self, "policy_data") and self.policy_data is not None:
            if isinstance(self.policy_data, dict):
                _dict["policy_data"] = self.policy_data
            else:
                _dict["policy_data"] = self.policy_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePolicyMetricsResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "GetInstancePolicyMetricsResourcesItem") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "GetInstancePolicyMetricsResourcesItem") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePolicyRotationResourcesItem:
    """
    GetInstancePolicyRotationResourcesItem.

    :param datetime creation_date: (optional) The date the policy was created. The
          date format follows RFC 3339.
    :param str created_by: (optional) The unique identifier for the resource that
          created the policy.
    :param str updated_by: (optional) The unique identifier for the resource that
          updated the policy.
    :param datetime last_updated: (optional) Updates when the policy is replaced or
          modified. The date format follows RFC 3339.
    :param str policy_type: The type of policy to be retrieved.
    :param GetInstancePolicyRotationResourcesItemPolicyData policy_data: User
          defined metadata that is associated with the `rotation` instance policy type.
    """

    def __init__(
        self,
        policy_type: str,
        policy_data: "GetInstancePolicyRotationResourcesItemPolicyData",
        *,
        creation_date: Optional[datetime] = None,
        created_by: Optional[str] = None,
        updated_by: Optional[str] = None,
        last_updated: Optional[datetime] = None,
    ) -> None:
        """
        Initialize a GetInstancePolicyRotationResourcesItem object.

        :param str policy_type: The type of policy to be retrieved.
        :param GetInstancePolicyRotationResourcesItemPolicyData policy_data: User
               defined metadata that is associated with the `rotation` instance policy
               type.
        """
        self.creation_date = creation_date
        self.created_by = created_by
        self.updated_by = updated_by
        self.last_updated = last_updated
        self.policy_type = policy_type
        self.policy_data = policy_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> "GetInstancePolicyRotationResourcesItem":
        """Initialize a GetInstancePolicyRotationResourcesItem object from a json dictionary."""
        args = {}
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (created_by := _dict.get("createdBy")) is not None:
            args["created_by"] = created_by
        if (updated_by := _dict.get("updatedBy")) is not None:
            args["updated_by"] = updated_by
        if (last_updated := _dict.get("lastUpdated")) is not None:
            args["last_updated"] = string_to_datetime(last_updated)
        if (policy_type := _dict.get("policy_type")) is not None:
            args["policy_type"] = policy_type
        else:
            raise ValueError(
                "Required property 'policy_type' not present in GetInstancePolicyRotationResourcesItem JSON"
            )
        if (policy_data := _dict.get("policy_data")) is not None:
            args["policy_data"] = (
                GetInstancePolicyRotationResourcesItemPolicyData.from_dict(policy_data)
            )
        else:
            raise ValueError(
                "Required property 'policy_data' not present in GetInstancePolicyRotationResourcesItem JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePolicyRotationResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        if hasattr(self, "created_by") and getattr(self, "created_by") is not None:
            _dict["createdBy"] = getattr(self, "created_by")
        if hasattr(self, "updated_by") and getattr(self, "updated_by") is not None:
            _dict["updatedBy"] = getattr(self, "updated_by")
        if hasattr(self, "last_updated") and getattr(self, "last_updated") is not None:
            _dict["lastUpdated"] = datetime_to_string(getattr(self, "last_updated"))
        if hasattr(self, "policy_type") and self.policy_type is not None:
            _dict["policy_type"] = self.policy_type
        if hasattr(self, "policy_data") and self.policy_data is not None:
            if isinstance(self.policy_data, dict):
                _dict["policy_data"] = self.policy_data
            else:
                _dict["policy_data"] = self.policy_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePolicyRotationResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "GetInstancePolicyRotationResourcesItem") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "GetInstancePolicyRotationResourcesItem") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePolicyRotationResourcesItemPolicyData:
    """
    User defined metadata that is associated with the `rotation` instance policy type.

    :param bool enabled: If set to `true`, Key Protect enables the specified policy
          for your service instance. If set to `false`, Key Protect disables the specified
          policy for your service instance, and the policy will no longer affect Key
          Protect actions.
          **Note:** If a policy with attributes is disabled, all attributes are reset and
          are not retained.
    :param GetInstancePolicyRotationResourcesItemPolicyDataAttributes attributes:
          (optional) Data associated with the policy type `rotation`.
    """

    def __init__(
        self,
        enabled: bool,
        *,
        attributes: Optional[
            "GetInstancePolicyRotationResourcesItemPolicyDataAttributes"
        ] = None,
    ) -> None:
        """
        Initialize a GetInstancePolicyRotationResourcesItemPolicyData object.

        :param bool enabled: If set to `true`, Key Protect enables the specified
               policy for your service instance. If set to `false`, Key Protect disables
               the specified policy for your service instance, and the policy will no
               longer affect Key Protect actions.
               **Note:** If a policy with attributes is disabled, all attributes are reset
               and are not retained.
        :param GetInstancePolicyRotationResourcesItemPolicyDataAttributes
               attributes: (optional) Data associated with the policy type `rotation`.
        """
        self.enabled = enabled
        self.attributes = attributes

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePolicyRotationResourcesItemPolicyData":
        """Initialize a GetInstancePolicyRotationResourcesItemPolicyData object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            args["enabled"] = None
        if (attributes := _dict.get("attributes")) is not None:
            args["attributes"] = (
                GetInstancePolicyRotationResourcesItemPolicyDataAttributes.from_dict(
                    attributes
                )
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePolicyRotationResourcesItemPolicyData object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        if hasattr(self, "attributes") and self.attributes is not None:
            if isinstance(self.attributes, dict):
                _dict["attributes"] = self.attributes
            else:
                _dict["attributes"] = self.attributes.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePolicyRotationResourcesItemPolicyData object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "GetInstancePolicyRotationResourcesItemPolicyData") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "GetInstancePolicyRotationResourcesItemPolicyData") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePolicyRotationResourcesItemPolicyDataAttributes:
    """
    Data associated with the policy type `rotation`.

    :param int interval_month: Specifies the key rotation time interval in
          approximate months, where a month is equivalent to 30 days. A minimum of 1 and a
          maximum of 12 can be set.
    """

    def __init__(
        self,
        interval_month: int,
    ) -> None:
        """
        Initialize a GetInstancePolicyRotationResourcesItemPolicyDataAttributes object.

        :param int interval_month: Specifies the key rotation time interval in
               approximate months, where a month is equivalent to 30 days. A minimum of 1
               and a maximum of 12 can be set.
        """
        self.interval_month = interval_month

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePolicyRotationResourcesItemPolicyDataAttributes":
        """Initialize a GetInstancePolicyRotationResourcesItemPolicyDataAttributes object from a json dictionary."""
        args = {}
        if (interval_month := _dict.get("interval_month")) is not None:
            args["interval_month"] = interval_month
        else:
            args["interval_month"] = None
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePolicyRotationResourcesItemPolicyDataAttributes object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "interval_month") and self.interval_month is not None:
            _dict["interval_month"] = self.interval_month
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePolicyRotationResourcesItemPolicyDataAttributes object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "GetInstancePolicyRotationResourcesItemPolicyDataAttributes"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "GetInstancePolicyRotationResourcesItemPolicyDataAttributes"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetKey:
    """
    The base schema for retrieving keys.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param List[KeyWithPayload] resources: A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List["KeyWithPayload"],
    ) -> None:
        """
        Initialize a GetKey object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[KeyWithPayload] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "GetKey":
        """Initialize a GetKey object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError("Required property 'metadata' not present in GetKey JSON")
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [KeyWithPayload.from_dict(v) for v in resources]
        else:
            raise ValueError("Required property 'resources' not present in GetKey JSON")
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetKey object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetKey object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "GetKey") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "GetKey") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetKeyMetadata:
    """
    The base schema for retrieving key metadata.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param List[KeyFullRepresentation] resources: A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List["KeyFullRepresentation"],
    ) -> None:
        """
        Initialize a GetKeyMetadata object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[KeyFullRepresentation] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "GetKeyMetadata":
        """Initialize a GetKeyMetadata object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in GetKeyMetadata JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [KeyFullRepresentation.from_dict(v) for v in resources]
        else:
            raise ValueError(
                "Required property 'resources' not present in GetKeyMetadata JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetKeyMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetKeyMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "GetKeyMetadata") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "GetKeyMetadata") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetKeyPoliciesOneOf:
    """
    GetKeyPoliciesOneOf.

    """

    def __init__(
        self,
    ) -> None:
        """
        Initialize a GetKeyPoliciesOneOf object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(
                [
                    "GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete",
                    "GetKeyPoliciesOneOfGetKeyPolicyRotation",
                    "GetKeyPoliciesOneOfGetMultipleKeyPolicies",
                ]
            )
        )
        raise Exception(msg)


class GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem:
    """
    Properties that are associated with key level dual authorization delete policy.

    :param str id: (optional) The v4 UUID used to uniquely identify the policy
          resource, as specified by RFC 4122.
    :param str crn: (optional) The Cloud Resource Name (CRN) that uniquely
          identifies your cloud resources.
    :param datetime creation_date: (optional) The date the policy was created. The
          date format follows RFC 3339.
    :param str created_by: (optional) The unique identifier for the resource that
          created the policy.
    :param datetime last_update_date: (optional) Updates when the policy is replaced
          or modified. The date format follows RFC 3339.
    :param str updated_by: (optional) The unique identifier for the resource that
          updated the policy.
    :param str type: Specifies the MIME type that represents the policy resource.
          Currently, only the default is supported.
    :param KeyPolicyDualAuthDeleteDualAuthDelete dual_auth_delete: Data associated
          with the dual authorization delete policy.
    """

    def __init__(
        self,
        type: str,
        dual_auth_delete: "KeyPolicyDualAuthDeleteDualAuthDelete",
        *,
        id: Optional[str] = None,
        crn: Optional[str] = None,
        creation_date: Optional[datetime] = None,
        created_by: Optional[str] = None,
        last_update_date: Optional[datetime] = None,
        updated_by: Optional[str] = None,
    ) -> None:
        """
        Initialize a GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem object.

        :param str type: Specifies the MIME type that represents the policy
               resource. Currently, only the default is supported.
        :param KeyPolicyDualAuthDeleteDualAuthDelete dual_auth_delete: Data
               associated with the dual authorization delete policy.
        """
        self.id = id
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.updated_by = updated_by
        self.type = type
        self.dual_auth_delete = dual_auth_delete

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem":
        """Initialize a GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem object from a json dictionary."""
        args = {}
        if (id := _dict.get("id")) is not None:
            args["id"] = id
        if (crn := _dict.get("crn")) is not None:
            args["crn"] = crn
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (created_by := _dict.get("createdBy")) is not None:
            args["created_by"] = created_by
        if (last_update_date := _dict.get("lastUpdateDate")) is not None:
            args["last_update_date"] = string_to_datetime(last_update_date)
        if (updated_by := _dict.get("updatedBy")) is not None:
            args["updated_by"] = updated_by
        if (type := _dict.get("type")) is not None:
            args["type"] = type
        else:
            raise ValueError(
                "Required property 'type' not present in GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem JSON"
            )
        if (dual_auth_delete := _dict.get("dualAuthDelete")) is not None:
            args["dual_auth_delete"] = KeyPolicyDualAuthDeleteDualAuthDelete.from_dict(
                dual_auth_delete
            )
        else:
            args["dual_auth_delete"] = None
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "id") and getattr(self, "id") is not None:
            _dict["id"] = getattr(self, "id")
        if hasattr(self, "crn") and getattr(self, "crn") is not None:
            _dict["crn"] = getattr(self, "crn")
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        if hasattr(self, "created_by") and getattr(self, "created_by") is not None:
            _dict["createdBy"] = getattr(self, "created_by")
        if (
            hasattr(self, "last_update_date")
            and getattr(self, "last_update_date") is not None
        ):
            _dict["lastUpdateDate"] = datetime_to_string(
                getattr(self, "last_update_date")
            )
        if hasattr(self, "updated_by") and getattr(self, "updated_by") is not None:
            _dict["updatedBy"] = getattr(self, "updated_by")
        if hasattr(self, "type") and self.type is not None:
            _dict["type"] = self.type
        if hasattr(self, "dual_auth_delete") and self.dual_auth_delete is not None:
            if isinstance(self.dual_auth_delete, dict):
                _dict["dualAuthDelete"] = self.dual_auth_delete
            else:
                _dict["dualAuthDelete"] = self.dual_auth_delete.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        Specifies the MIME type that represents the policy resource. Currently, only the
        default is supported.
        """

        APPLICATION_VND_IBM_KMS_POLICY_JSON = "application/vnd.ibm.kms.policy+json"


class GetKeyPolicyRotationResourcesItem:
    """
    Properties that are associated with rotation policy.

    :param str id: (optional) The v4 UUID used to uniquely identify the policy
          resource, as specified by RFC 4122.
    :param str crn: (optional) The Cloud Resource Name (CRN) that uniquely
          identifies your cloud resources.
    :param datetime creation_date: (optional) The date the policy was created. The
          date format follows RFC 3339.
    :param str created_by: (optional) The unique identifier for the resource that
          created the policy.
    :param datetime last_update_date: (optional) Updates when the policy is replaced
          or modified. The date format follows RFC 3339.
    :param str updated_by: (optional) The unique identifier for the resource that
          updated the policy.
    :param str type: Specifies the MIME type that represents the policy resource.
          Currently, only the default is supported.
    :param KeyPolicyRotationRotation rotation: Data associated with the automatic
          key rotation policy.
    """

    def __init__(
        self,
        type: str,
        rotation: "KeyPolicyRotationRotation",
        *,
        id: Optional[str] = None,
        crn: Optional[str] = None,
        creation_date: Optional[datetime] = None,
        created_by: Optional[str] = None,
        last_update_date: Optional[datetime] = None,
        updated_by: Optional[str] = None,
    ) -> None:
        """
        Initialize a GetKeyPolicyRotationResourcesItem object.

        :param str type: Specifies the MIME type that represents the policy
               resource. Currently, only the default is supported.
        :param KeyPolicyRotationRotation rotation: Data associated with the
               automatic key rotation policy.
        """
        self.id = id
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.updated_by = updated_by
        self.type = type
        self.rotation = rotation

    @classmethod
    def from_dict(cls, _dict: Dict) -> "GetKeyPolicyRotationResourcesItem":
        """Initialize a GetKeyPolicyRotationResourcesItem object from a json dictionary."""
        args = {}
        if (id := _dict.get("id")) is not None:
            args["id"] = id
        if (crn := _dict.get("crn")) is not None:
            args["crn"] = crn
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (created_by := _dict.get("createdBy")) is not None:
            args["created_by"] = created_by
        if (last_update_date := _dict.get("lastUpdateDate")) is not None:
            args["last_update_date"] = string_to_datetime(last_update_date)
        if (updated_by := _dict.get("updatedBy")) is not None:
            args["updated_by"] = updated_by
        if (type := _dict.get("type")) is not None:
            args["type"] = type
        else:
            raise ValueError(
                "Required property 'type' not present in GetKeyPolicyRotationResourcesItem JSON"
            )
        if (rotation := _dict.get("rotation")) is not None:
            args["rotation"] = KeyPolicyRotationRotation.from_dict(rotation)
        else:
            args["rotation"] = None
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetKeyPolicyRotationResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "id") and getattr(self, "id") is not None:
            _dict["id"] = getattr(self, "id")
        if hasattr(self, "crn") and getattr(self, "crn") is not None:
            _dict["crn"] = getattr(self, "crn")
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        if hasattr(self, "created_by") and getattr(self, "created_by") is not None:
            _dict["createdBy"] = getattr(self, "created_by")
        if (
            hasattr(self, "last_update_date")
            and getattr(self, "last_update_date") is not None
        ):
            _dict["lastUpdateDate"] = datetime_to_string(
                getattr(self, "last_update_date")
            )
        if hasattr(self, "updated_by") and getattr(self, "updated_by") is not None:
            _dict["updatedBy"] = getattr(self, "updated_by")
        if hasattr(self, "type") and self.type is not None:
            _dict["type"] = self.type
        if hasattr(self, "rotation") and self.rotation is not None:
            if isinstance(self.rotation, dict):
                _dict["rotation"] = self.rotation
            else:
                _dict["rotation"] = self.rotation.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetKeyPolicyRotationResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "GetKeyPolicyRotationResourcesItem") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "GetKeyPolicyRotationResourcesItem") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        Specifies the MIME type that represents the policy resource. Currently, only the
        default is supported.
        """

        APPLICATION_VND_IBM_KMS_POLICY_JSON = "application/vnd.ibm.kms.policy+json"


class GetMultipleKeyPoliciesResource:
    """
    Properties that are associated with rotation policy.

    :param GetMultipleKeyPoliciesResourceDualAuthDelete dual_auth_delete: (optional)
          Data associated with the dual authorization delete policy.
    :param KeyPolicyRotationNonRequiredRotation rotation: (optional) Data associated
          with the automatic key rotation policy.
    :param str id: (optional) The v4 UUID used to uniquely identify the policy
          resource, as specified by RFC 4122.
    :param str crn: (optional) The Cloud Resource Name (CRN) that uniquely
          identifies your cloud resources.
    :param datetime creation_date: (optional) The date the policy was created. The
          date format follows RFC 3339.
    :param str created_by: (optional) The unique identifier for the resource that
          created the policy.
    :param datetime last_update_date: (optional) Updates when the policy is replaced
          or modified. The date format follows RFC 3339.
    :param str updated_by: (optional) The unique identifier for the resource that
          updated the policy.
    """

    def __init__(
        self,
        *,
        dual_auth_delete: Optional[
            "GetMultipleKeyPoliciesResourceDualAuthDelete"
        ] = None,
        rotation: Optional["KeyPolicyRotationNonRequiredRotation"] = None,
        id: Optional[str] = None,
        crn: Optional[str] = None,
        creation_date: Optional[datetime] = None,
        created_by: Optional[str] = None,
        last_update_date: Optional[datetime] = None,
        updated_by: Optional[str] = None,
    ) -> None:
        """
        Initialize a GetMultipleKeyPoliciesResource object.

        :param GetMultipleKeyPoliciesResourceDualAuthDelete dual_auth_delete:
               (optional) Data associated with the dual authorization delete policy.
        :param KeyPolicyRotationNonRequiredRotation rotation: (optional) Data
               associated with the automatic key rotation policy.
        """
        self.dual_auth_delete = dual_auth_delete
        self.rotation = rotation
        self.id = id
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.updated_by = updated_by

    @classmethod
    def from_dict(cls, _dict: Dict) -> "GetMultipleKeyPoliciesResource":
        """Initialize a GetMultipleKeyPoliciesResource object from a json dictionary."""
        args = {}
        if (dual_auth_delete := _dict.get("dualAuthDelete")) is not None:
            args["dual_auth_delete"] = (
                GetMultipleKeyPoliciesResourceDualAuthDelete.from_dict(dual_auth_delete)
            )
        if (rotation := _dict.get("rotation")) is not None:
            args["rotation"] = KeyPolicyRotationNonRequiredRotation.from_dict(rotation)
        if (id := _dict.get("id")) is not None:
            args["id"] = id
        if (crn := _dict.get("crn")) is not None:
            args["crn"] = crn
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (created_by := _dict.get("createdBy")) is not None:
            args["created_by"] = created_by
        if (last_update_date := _dict.get("lastUpdateDate")) is not None:
            args["last_update_date"] = string_to_datetime(last_update_date)
        if (updated_by := _dict.get("updatedBy")) is not None:
            args["updated_by"] = updated_by
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetMultipleKeyPoliciesResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "dual_auth_delete") and self.dual_auth_delete is not None:
            if isinstance(self.dual_auth_delete, dict):
                _dict["dualAuthDelete"] = self.dual_auth_delete
            else:
                _dict["dualAuthDelete"] = self.dual_auth_delete.to_dict()
        if hasattr(self, "rotation") and self.rotation is not None:
            if isinstance(self.rotation, dict):
                _dict["rotation"] = self.rotation
            else:
                _dict["rotation"] = self.rotation.to_dict()
        if hasattr(self, "id") and getattr(self, "id") is not None:
            _dict["id"] = getattr(self, "id")
        if hasattr(self, "crn") and getattr(self, "crn") is not None:
            _dict["crn"] = getattr(self, "crn")
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        if hasattr(self, "created_by") and getattr(self, "created_by") is not None:
            _dict["createdBy"] = getattr(self, "created_by")
        if (
            hasattr(self, "last_update_date")
            and getattr(self, "last_update_date") is not None
        ):
            _dict["lastUpdateDate"] = datetime_to_string(
                getattr(self, "last_update_date")
            )
        if hasattr(self, "updated_by") and getattr(self, "updated_by") is not None:
            _dict["updatedBy"] = getattr(self, "updated_by")
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetMultipleKeyPoliciesResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "GetMultipleKeyPoliciesResource") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "GetMultipleKeyPoliciesResource") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetMultipleKeyPoliciesResourceDualAuthDelete:
    """
    Data associated with the dual authorization delete policy.

    :param bool enabled: If set to `true`, Key Protect enables a dual authorization
          policy on a single key. After you enable the policy, Key Protect requires an
          authorization from two users to delete this key. For example, you can authorize
          the deletion first by using the [SetKeyForDeletion](#invoke-an-action-on-a-key)
          action. Then, a different user provides a second authorization implicitly by
          calling `DELETE /keys` to delete the key.
          **Note:** Once the dual authorization policy is set on the key, it cannot be
          reverted.
    """

    def __init__(
        self,
        enabled: bool,
    ) -> None:
        """
        Initialize a GetMultipleKeyPoliciesResourceDualAuthDelete object.

        :param bool enabled: If set to `true`, Key Protect enables a dual
               authorization policy on a single key. After you enable the policy, Key
               Protect requires an authorization from two users to delete this key. For
               example, you can authorize the deletion first by using the
               [SetKeyForDeletion](#invoke-an-action-on-a-key) action. Then, a different
               user provides a second authorization implicitly by calling `DELETE /keys`
               to delete the key.
               **Note:** Once the dual authorization policy is set on the key, it cannot
               be reverted.
        """
        self.enabled = enabled

    @classmethod
    def from_dict(cls, _dict: Dict) -> "GetMultipleKeyPoliciesResourceDualAuthDelete":
        """Initialize a GetMultipleKeyPoliciesResourceDualAuthDelete object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            raise ValueError(
                "Required property 'enabled' not present in GetMultipleKeyPoliciesResourceDualAuthDelete JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetMultipleKeyPoliciesResourceDualAuthDelete object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetMultipleKeyPoliciesResourceDualAuthDelete object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "GetMultipleKeyPoliciesResourceDualAuthDelete") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "GetMultipleKeyPoliciesResourceDualAuthDelete") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ImportToken:
    """
    Properties that are associated with import tokens.

    :param float expiration: (optional) The time in seconds from the creation of an
          import token that determines how long its associated public key remains valid.
          The minimum value is `300` seconds (5 minutes), and the maximum value is `86400`
          (24 hours). The default value is `600` (10 minutes).
    :param float max_allowed_retrievals: (optional) The number of times that an
          import token can be retrieved within its expiration time before it is no longer
          accessible.
    :param datetime creation_date: (optional) The date the import token was created.
          The date format follows RFC 3339.
    :param datetime expiration_date: (optional) The date the import token expires.
          The date format follows RFC 3339.
    :param float remaining_retrievals: (optional) The number of retrievals that are
          available for the import token before it is no longer accessible.
    """

    def __init__(
        self,
        *,
        expiration: Optional[float] = None,
        max_allowed_retrievals: Optional[float] = None,
        creation_date: Optional[datetime] = None,
        expiration_date: Optional[datetime] = None,
        remaining_retrievals: Optional[float] = None,
    ) -> None:
        """
        Initialize a ImportToken object.

        :param float expiration: (optional) The time in seconds from the creation
               of an import token that determines how long its associated public key
               remains valid. The minimum value is `300` seconds (5 minutes), and the
               maximum value is `86400` (24 hours). The default value is `600` (10
               minutes).
        :param float max_allowed_retrievals: (optional) The number of times that an
               import token can be retrieved within its expiration time before it is no
               longer accessible.
        """
        self.expiration = expiration
        self.max_allowed_retrievals = max_allowed_retrievals
        self.creation_date = creation_date
        self.expiration_date = expiration_date
        self.remaining_retrievals = remaining_retrievals

    @classmethod
    def from_dict(cls, _dict: Dict) -> "ImportToken":
        """Initialize a ImportToken object from a json dictionary."""
        args = {}
        if (expiration := _dict.get("expiration")) is not None:
            args["expiration"] = expiration
        if (max_allowed_retrievals := _dict.get("maxAllowedRetrievals")) is not None:
            args["max_allowed_retrievals"] = max_allowed_retrievals
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (expiration_date := _dict.get("expirationDate")) is not None:
            args["expiration_date"] = string_to_datetime(expiration_date)
        if (remaining_retrievals := _dict.get("remainingRetrievals")) is not None:
            args["remaining_retrievals"] = remaining_retrievals
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ImportToken object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "expiration") and self.expiration is not None:
            _dict["expiration"] = self.expiration
        if (
            hasattr(self, "max_allowed_retrievals")
            and self.max_allowed_retrievals is not None
        ):
            _dict["maxAllowedRetrievals"] = self.max_allowed_retrievals
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        if (
            hasattr(self, "expiration_date")
            and getattr(self, "expiration_date") is not None
        ):
            _dict["expirationDate"] = datetime_to_string(
                getattr(self, "expiration_date")
            )
        if (
            hasattr(self, "remaining_retrievals")
            and getattr(self, "remaining_retrievals") is not None
        ):
            _dict["remainingRetrievals"] = getattr(self, "remaining_retrievals")
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ImportToken object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "ImportToken") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "ImportToken") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class InstancePolicyAllowedIPPolicyData:
    """
    User defined metadata that is associated with the `allowedIP` instance policy type.

    :param bool enabled: If set to `true`, Key Protect enables the specified policy
          for your service instance. If set to `false`, Key Protect disables the specified
          policy for your service instance, and the policy will no longer affect Key
          Protect actions.
          **Note:** If a policy with attributes is disabled, all attributes are reset and
          are not retained.
    :param InstancePolicyAllowedIPPolicyDataAttributes attributes: (optional)
          Attributes of an `allowedIP` instance policy. Must be provided if the `enabled`
          field is `true`. Cannot be provided if the `enabled` field is `false`.
    """

    def __init__(
        self,
        enabled: bool,
        *,
        attributes: Optional["InstancePolicyAllowedIPPolicyDataAttributes"] = None,
    ) -> None:
        """
        Initialize a InstancePolicyAllowedIPPolicyData object.

        :param bool enabled: If set to `true`, Key Protect enables the specified
               policy for your service instance. If set to `false`, Key Protect disables
               the specified policy for your service instance, and the policy will no
               longer affect Key Protect actions.
               **Note:** If a policy with attributes is disabled, all attributes are reset
               and are not retained.
        :param InstancePolicyAllowedIPPolicyDataAttributes attributes: (optional)
               Attributes of an `allowedIP` instance policy. Must be provided if the
               `enabled` field is `true`. Cannot be provided if the `enabled` field is
               `false`.
        """
        self.enabled = enabled
        self.attributes = attributes

    @classmethod
    def from_dict(cls, _dict: Dict) -> "InstancePolicyAllowedIPPolicyData":
        """Initialize a InstancePolicyAllowedIPPolicyData object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            args["enabled"] = None
        if (attributes := _dict.get("attributes")) is not None:
            args["attributes"] = InstancePolicyAllowedIPPolicyDataAttributes.from_dict(
                attributes
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a InstancePolicyAllowedIPPolicyData object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        if hasattr(self, "attributes") and self.attributes is not None:
            if isinstance(self.attributes, dict):
                _dict["attributes"] = self.attributes
            else:
                _dict["attributes"] = self.attributes.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this InstancePolicyAllowedIPPolicyData object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "InstancePolicyAllowedIPPolicyData") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "InstancePolicyAllowedIPPolicyData") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class InstancePolicyAllowedIPPolicyDataAttributes:
    """
    Attributes of an `allowedIP` instance policy. Must be provided if the `enabled` field
    is `true`. Cannot be provided if the `enabled` field is `false`.

    :param List[str] allowed_ip: (optional) A string array of IPv4 or IPv6 CIDR
          notated subnets that are authorized to interact with the instance. If both
          `allowedNetwork` and `allowedIP` policies are set, only traffic aligning with
          both the `allowed_network` allowed network policy attribute and the `allowed_ip`
          allowed IP policy attribute will be allowed. IPv4 and iIP6 addresses are
          accepted for public endpoints. Only the IPv4 private network gateway addresses
          from the array will be authorized to access your instance via private endpoint.
          **Important:** Once set, accessing your instance may require additional steps.
          For more information, see [Accessing an instance via public
          endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-public-endpoint)
          and [Accessing an instance via private
          endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-private-endpoint)
          for more details.
          **Note:** An allowed IP policy does not affect requests from other IBM Cloud
          services.
    """

    def __init__(
        self,
        *,
        allowed_ip: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a InstancePolicyAllowedIPPolicyDataAttributes object.

        :param List[str] allowed_ip: (optional) A string array of IPv4 or IPv6 CIDR
               notated subnets that are authorized to interact with the instance. If both
               `allowedNetwork` and `allowedIP` policies are set, only traffic aligning
               with both the `allowed_network` allowed network policy attribute and the
               `allowed_ip` allowed IP policy attribute will be allowed. IPv4 and iIP6
               addresses are accepted for public endpoints. Only the IPv4 private network
               gateway addresses from the array will be authorized to access your instance
               via private endpoint.
               **Important:** Once set, accessing your instance may require additional
               steps. For more information, see [Accessing an instance via public
               endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-public-endpoint)
               and [Accessing an instance via private
               endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-private-endpoint)
               for more details.
               **Note:** An allowed IP policy does not affect requests from other IBM
               Cloud services.
        """
        self.allowed_ip = allowed_ip

    @classmethod
    def from_dict(cls, _dict: Dict) -> "InstancePolicyAllowedIPPolicyDataAttributes":
        """Initialize a InstancePolicyAllowedIPPolicyDataAttributes object from a json dictionary."""
        args = {}
        if (allowed_ip := _dict.get("allowed_ip")) is not None:
            args["allowed_ip"] = allowed_ip
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a InstancePolicyAllowedIPPolicyDataAttributes object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "allowed_ip") and self.allowed_ip is not None:
            _dict["allowed_ip"] = self.allowed_ip
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this InstancePolicyAllowedIPPolicyDataAttributes object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "InstancePolicyAllowedIPPolicyDataAttributes") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "InstancePolicyAllowedIPPolicyDataAttributes") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class InstancePolicyAllowedNetworkPolicyData:
    """
    User defined metadata that is associated with the `allowedNetwork` instance policy
    type.

    :param bool enabled: If set to `true`, Key Protect enables the specified policy
          for your service instance. If set to `false`, Key Protect disables the specified
          policy for your service instance, and the policy will no longer affect Key
          Protect actions.
          **Note:** If a policy with attributes is disabled, all attributes are reset and
          are not retained.
    :param InstancePolicyAllowedNetworkPolicyDataAttributes attributes: (optional)
          Attributes of an `allowedNetwork` instance policy. Must be provided if the
          `enabled` field is `true`. Cannot be provided if the `enabled` field is `false`.
    """

    def __init__(
        self,
        enabled: bool,
        *,
        attributes: Optional["InstancePolicyAllowedNetworkPolicyDataAttributes"] = None,
    ) -> None:
        """
        Initialize a InstancePolicyAllowedNetworkPolicyData object.

        :param bool enabled: If set to `true`, Key Protect enables the specified
               policy for your service instance. If set to `false`, Key Protect disables
               the specified policy for your service instance, and the policy will no
               longer affect Key Protect actions.
               **Note:** If a policy with attributes is disabled, all attributes are reset
               and are not retained.
        :param InstancePolicyAllowedNetworkPolicyDataAttributes attributes:
               (optional) Attributes of an `allowedNetwork` instance policy. Must be
               provided if the `enabled` field is `true`. Cannot be provided if the
               `enabled` field is `false`.
        """
        self.enabled = enabled
        self.attributes = attributes

    @classmethod
    def from_dict(cls, _dict: Dict) -> "InstancePolicyAllowedNetworkPolicyData":
        """Initialize a InstancePolicyAllowedNetworkPolicyData object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            args["enabled"] = None
        if (attributes := _dict.get("attributes")) is not None:
            args["attributes"] = (
                InstancePolicyAllowedNetworkPolicyDataAttributes.from_dict(attributes)
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a InstancePolicyAllowedNetworkPolicyData object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        if hasattr(self, "attributes") and self.attributes is not None:
            if isinstance(self.attributes, dict):
                _dict["attributes"] = self.attributes
            else:
                _dict["attributes"] = self.attributes.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this InstancePolicyAllowedNetworkPolicyData object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "InstancePolicyAllowedNetworkPolicyData") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "InstancePolicyAllowedNetworkPolicyData") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class InstancePolicyAllowedNetworkPolicyDataAttributes:
    """
    Attributes of an `allowedNetwork` instance policy. Must be provided if the `enabled`
    field is `true`. Cannot be provided if the `enabled` field is `false`.

    :param str allowed_network: If set to `public-and-private`, Key Protect allows
          the instance to be accessible through public and private endpoints. If set to
          `private-only`, Key Protect restricts the instance to only be accessible through
          a private endpoint.
    """

    def __init__(
        self,
        allowed_network: str,
    ) -> None:
        """
        Initialize a InstancePolicyAllowedNetworkPolicyDataAttributes object.

        :param str allowed_network: If set to `public-and-private`, Key Protect
               allows the instance to be accessible through public and private endpoints.
               If set to `private-only`, Key Protect restricts the instance to only be
               accessible through a private endpoint.
        """
        self.allowed_network = allowed_network

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "InstancePolicyAllowedNetworkPolicyDataAttributes":
        """Initialize a InstancePolicyAllowedNetworkPolicyDataAttributes object from a json dictionary."""
        args = {}
        if (allowed_network := _dict.get("allowed_network")) is not None:
            args["allowed_network"] = allowed_network
        else:
            args["allowed_network"] = None
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a InstancePolicyAllowedNetworkPolicyDataAttributes object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "allowed_network") and self.allowed_network is not None:
            _dict["allowed_network"] = self.allowed_network
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this InstancePolicyAllowedNetworkPolicyDataAttributes object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "InstancePolicyAllowedNetworkPolicyDataAttributes") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "InstancePolicyAllowedNetworkPolicyDataAttributes") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class AllowedNetworkEnum(str, Enum):
        """
        If set to `public-and-private`, Key Protect allows the instance to be accessible
        through public and private endpoints. If set to `private-only`, Key Protect
        restricts the instance to only be accessible through a private endpoint.
        """

        PUBLIC_AND_PRIVATE = "public-and-private"
        PRIVATE_ONLY = "private-only"


class InstancePolicyKeyCreateImportAccessPolicyData:
    """
    User defined metadata that is associated with the `keyCreateImportAccess` instance
    policy type.

    :param bool enabled: If set to `true`, Key Protect enables the specified policy
          for your service instance. If set to `false`, Key Protect disables the specified
          policy for your service instance, and the policy will no longer affect Key
          Protect actions.
          **Note:** If a policy with attributes is disabled, all attributes are reset and
          are not retained.
    :param InstancePolicyKeyCreateImportAccessPolicyDataAttributes attributes:
          (optional) Attributes of a `keyCreateImportAccess` instance policy. Must be
          provided if the `enabled` field is `true`. Cannot be provided if the `enabled`
          field is `false`.
    """

    def __init__(
        self,
        enabled: bool,
        *,
        attributes: Optional[
            "InstancePolicyKeyCreateImportAccessPolicyDataAttributes"
        ] = None,
    ) -> None:
        """
        Initialize a InstancePolicyKeyCreateImportAccessPolicyData object.

        :param bool enabled: If set to `true`, Key Protect enables the specified
               policy for your service instance. If set to `false`, Key Protect disables
               the specified policy for your service instance, and the policy will no
               longer affect Key Protect actions.
               **Note:** If a policy with attributes is disabled, all attributes are reset
               and are not retained.
        :param InstancePolicyKeyCreateImportAccessPolicyDataAttributes attributes:
               (optional) Attributes of a `keyCreateImportAccess` instance policy. Must be
               provided if the `enabled` field is `true`. Cannot be provided if the
               `enabled` field is `false`.
        """
        self.enabled = enabled
        self.attributes = attributes

    @classmethod
    def from_dict(cls, _dict: Dict) -> "InstancePolicyKeyCreateImportAccessPolicyData":
        """Initialize a InstancePolicyKeyCreateImportAccessPolicyData object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            args["enabled"] = None
        if (attributes := _dict.get("attributes")) is not None:
            args["attributes"] = (
                InstancePolicyKeyCreateImportAccessPolicyDataAttributes.from_dict(
                    attributes
                )
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a InstancePolicyKeyCreateImportAccessPolicyData object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        if hasattr(self, "attributes") and self.attributes is not None:
            if isinstance(self.attributes, dict):
                _dict["attributes"] = self.attributes
            else:
                _dict["attributes"] = self.attributes.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this InstancePolicyKeyCreateImportAccessPolicyData object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "InstancePolicyKeyCreateImportAccessPolicyData") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "InstancePolicyKeyCreateImportAccessPolicyData") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class InstancePolicyKeyCreateImportAccessPolicyDataAttributes:
    """
    Attributes of a `keyCreateImportAccess` instance policy. Must be provided if the
    `enabled` field is `true`. Cannot be provided if the `enabled` field is `false`.

    :param bool create_root_key: (optional) If set to `false`, the service prevents
          you or any authorized users from using Key Protect to create root keys in the
          specified service instance. If set to `true`, Key Protect allows you or any
          authorized users to create root keys in the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool create_standard_key: (optional) If set to `false`, the service
          prevents you or any authorized users from using Key Protect to create standard
          keys in the specified service instance. If set to `true`, Key Protect allows you
          or any authorized users to create standard keys in the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool import_root_key: (optional) If set to `false`, the service prevents
          you or any authorized users from importing root keys into the specified service
          instance. If set to `true`, Key Protect allows you or any authorized users to
          import root keys into the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool import_standard_key: (optional) If set to `false`, the service
          prevents you or any authorized users from importing standard keys into the
          specified service instance. If set to `true`, Key Protect allows you or any
          authorized users to import standard keys into the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool enforce_token: (optional) If set to `true`, the service prevents you
          or any authorized users from importing key material into the specified service
          instance without using an import token. If set to `false`, Key Protect allows
          you or any authorized users to import key material into the instance without the
          use of an import token.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`false`).
    """

    def __init__(
        self,
        *,
        create_root_key: Optional[bool] = None,
        create_standard_key: Optional[bool] = None,
        import_root_key: Optional[bool] = None,
        import_standard_key: Optional[bool] = None,
        enforce_token: Optional[bool] = None,
    ) -> None:
        """
        Initialize a InstancePolicyKeyCreateImportAccessPolicyDataAttributes object.

        :param bool create_root_key: (optional) If set to `false`, the service
               prevents you or any authorized users from using Key Protect to create root
               keys in the specified service instance. If set to `true`, Key Protect
               allows you or any authorized users to create root keys in the instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool create_standard_key: (optional) If set to `false`, the service
               prevents you or any authorized users from using Key Protect to create
               standard keys in the specified service instance. If set to `true`, Key
               Protect allows you or any authorized users to create standard keys in the
               instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool import_root_key: (optional) If set to `false`, the service
               prevents you or any authorized users from importing root keys into the
               specified service instance. If set to `true`, Key Protect allows you or any
               authorized users to import root keys into the instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool import_standard_key: (optional) If set to `false`, the service
               prevents you or any authorized users from importing standard keys into the
               specified service instance. If set to `true`, Key Protect allows you or any
               authorized users to import standard keys into the instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool enforce_token: (optional) If set to `true`, the service
               prevents you or any authorized users from importing key material into the
               specified service instance without using an import token. If set to
               `false`, Key Protect allows you or any authorized users to import key
               material into the instance without the use of an import token.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`false`).
        """
        self.create_root_key = create_root_key
        self.create_standard_key = create_standard_key
        self.import_root_key = import_root_key
        self.import_standard_key = import_standard_key
        self.enforce_token = enforce_token

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "InstancePolicyKeyCreateImportAccessPolicyDataAttributes":
        """Initialize a InstancePolicyKeyCreateImportAccessPolicyDataAttributes object from a json dictionary."""
        args = {}
        if (create_root_key := _dict.get("create_root_key")) is not None:
            args["create_root_key"] = create_root_key
        if (create_standard_key := _dict.get("create_standard_key")) is not None:
            args["create_standard_key"] = create_standard_key
        if (import_root_key := _dict.get("import_root_key")) is not None:
            args["import_root_key"] = import_root_key
        if (import_standard_key := _dict.get("import_standard_key")) is not None:
            args["import_standard_key"] = import_standard_key
        if (enforce_token := _dict.get("enforce_token")) is not None:
            args["enforce_token"] = enforce_token
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a InstancePolicyKeyCreateImportAccessPolicyDataAttributes object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "create_root_key") and self.create_root_key is not None:
            _dict["create_root_key"] = self.create_root_key
        if (
            hasattr(self, "create_standard_key")
            and self.create_standard_key is not None
        ):
            _dict["create_standard_key"] = self.create_standard_key
        if hasattr(self, "import_root_key") and self.import_root_key is not None:
            _dict["import_root_key"] = self.import_root_key
        if (
            hasattr(self, "import_standard_key")
            and self.import_standard_key is not None
        ):
            _dict["import_standard_key"] = self.import_standard_key
        if hasattr(self, "enforce_token") and self.enforce_token is not None:
            _dict["enforce_token"] = self.enforce_token
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this InstancePolicyKeyCreateImportAccessPolicyDataAttributes object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "InstancePolicyKeyCreateImportAccessPolicyDataAttributes"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "InstancePolicyKeyCreateImportAccessPolicyDataAttributes"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class InstancePolicyProperties:
    """
    User defined metadata that is associated with any instance policy.

    :param bool enabled: If set to `true`, Key Protect enables the specified policy
          for your service instance. If set to `false`, Key Protect disables the specified
          policy for your service instance, and the policy will no longer affect Key
          Protect actions.
          **Note:** If a policy with attributes is disabled, all attributes are reset and
          are not retained.
    :param InstancePolicyPropertiesAttributes attributes: (optional) Attributes
          associated with any instance policy type.
    """

    def __init__(
        self,
        enabled: bool,
        *,
        attributes: Optional["InstancePolicyPropertiesAttributes"] = None,
    ) -> None:
        """
        Initialize a InstancePolicyProperties object.

        :param bool enabled: If set to `true`, Key Protect enables the specified
               policy for your service instance. If set to `false`, Key Protect disables
               the specified policy for your service instance, and the policy will no
               longer affect Key Protect actions.
               **Note:** If a policy with attributes is disabled, all attributes are reset
               and are not retained.
        :param InstancePolicyPropertiesAttributes attributes: (optional) Attributes
               associated with any instance policy type.
        """
        self.enabled = enabled
        self.attributes = attributes

    @classmethod
    def from_dict(cls, _dict: Dict) -> "InstancePolicyProperties":
        """Initialize a InstancePolicyProperties object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            args["enabled"] = None
        if (attributes := _dict.get("attributes")) is not None:
            args["attributes"] = InstancePolicyPropertiesAttributes.from_dict(
                attributes
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a InstancePolicyProperties object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        if hasattr(self, "attributes") and self.attributes is not None:
            if isinstance(self.attributes, dict):
                _dict["attributes"] = self.attributes
            else:
                _dict["attributes"] = self.attributes.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this InstancePolicyProperties object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "InstancePolicyProperties") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "InstancePolicyProperties") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class InstancePolicyPropertiesAttributes:
    """
    Attributes associated with any instance policy type.

    :param str allowed_network: (optional) If set to `public-and-private`, Key
          Protect allows the instance to be accessible through public and private
          endpoints. If set to `private-only`, Key Protect restricts the instance to only
          be accessible through a private endpoint.
    :param List[str] allowed_ip: (optional) A string array of IPv4 or IPv6 CIDR
          notated subnets that are authorized to interact with the instance. If both
          `allowedNetwork` and `allowedIP` policies are set, only traffic aligning with
          both the `allowed_network` allowed network policy attribute and the `allowed_ip`
          allowed IP policy attribute will be allowed. IPv4 and iIP6 addresses are
          accepted for public endpoints. Only the IPv4 private network gateway addresses
          from the array will be authorized to access your instance via private endpoint.
          **Important:** Once set, accessing your instance may require additional steps.
          For more information, see [Accessing an instance via public
          endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-public-endpoint)
          and [Accessing an instance via private
          endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-private-endpoint)
          for more details.
          **Note:** An allowed IP policy does not affect requests from other IBM Cloud
          services.
    :param bool create_root_key: (optional) If set to `false`, the service prevents
          you or any authorized users from using Key Protect to create root keys in the
          specified service instance. If set to `true`, Key Protect allows you or any
          authorized users to create root keys in the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool create_standard_key: (optional) If set to `false`, the service
          prevents you or any authorized users from using Key Protect to create standard
          keys in the specified service instance. If set to `true`, Key Protect allows you
          or any authorized users to create standard keys in the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool import_root_key: (optional) If set to `false`, the service prevents
          you or any authorized users from importing root keys into the specified service
          instance. If set to `true`, Key Protect allows you or any authorized users to
          import root keys into the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool import_standard_key: (optional) If set to `false`, the service
          prevents you or any authorized users from importing standard keys into the
          specified service instance. If set to `true`, Key Protect allows you or any
          authorized users to import standard keys into the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool enforce_token: (optional) If set to `true`, the service prevents you
          or any authorized users from importing key material into the specified service
          instance without using an import token. If set to `false`, Key Protect allows
          you or any authorized users to import key material into the instance without the
          use of an import token.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`false`).
    :param int interval_month: (optional) Specifies the key rotation time interval
          in approximate months, where a month is equivalent to 30 days. A minimum of 1
          and a maximum of 12 can be set.
    """

    def __init__(
        self,
        *,
        allowed_network: Optional[str] = None,
        allowed_ip: Optional[List[str]] = None,
        create_root_key: Optional[bool] = None,
        create_standard_key: Optional[bool] = None,
        import_root_key: Optional[bool] = None,
        import_standard_key: Optional[bool] = None,
        enforce_token: Optional[bool] = None,
        interval_month: Optional[int] = None,
    ) -> None:
        """
        Initialize a InstancePolicyPropertiesAttributes object.

        :param str allowed_network: (optional) If set to `public-and-private`, Key
               Protect allows the instance to be accessible through public and private
               endpoints. If set to `private-only`, Key Protect restricts the instance to
               only be accessible through a private endpoint.
        :param List[str] allowed_ip: (optional) A string array of IPv4 or IPv6 CIDR
               notated subnets that are authorized to interact with the instance. If both
               `allowedNetwork` and `allowedIP` policies are set, only traffic aligning
               with both the `allowed_network` allowed network policy attribute and the
               `allowed_ip` allowed IP policy attribute will be allowed. IPv4 and iIP6
               addresses are accepted for public endpoints. Only the IPv4 private network
               gateway addresses from the array will be authorized to access your instance
               via private endpoint.
               **Important:** Once set, accessing your instance may require additional
               steps. For more information, see [Accessing an instance via public
               endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-public-endpoint)
               and [Accessing an instance via private
               endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-private-endpoint)
               for more details.
               **Note:** An allowed IP policy does not affect requests from other IBM
               Cloud services.
        :param bool create_root_key: (optional) If set to `false`, the service
               prevents you or any authorized users from using Key Protect to create root
               keys in the specified service instance. If set to `true`, Key Protect
               allows you or any authorized users to create root keys in the instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool create_standard_key: (optional) If set to `false`, the service
               prevents you or any authorized users from using Key Protect to create
               standard keys in the specified service instance. If set to `true`, Key
               Protect allows you or any authorized users to create standard keys in the
               instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool import_root_key: (optional) If set to `false`, the service
               prevents you or any authorized users from importing root keys into the
               specified service instance. If set to `true`, Key Protect allows you or any
               authorized users to import root keys into the instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool import_standard_key: (optional) If set to `false`, the service
               prevents you or any authorized users from importing standard keys into the
               specified service instance. If set to `true`, Key Protect allows you or any
               authorized users to import standard keys into the instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool enforce_token: (optional) If set to `true`, the service
               prevents you or any authorized users from importing key material into the
               specified service instance without using an import token. If set to
               `false`, Key Protect allows you or any authorized users to import key
               material into the instance without the use of an import token.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`false`).
        :param int interval_month: (optional) Specifies the key rotation time
               interval in approximate months, where a month is equivalent to 30 days. A
               minimum of 1 and a maximum of 12 can be set.
        """
        self.allowed_network = allowed_network
        self.allowed_ip = allowed_ip
        self.create_root_key = create_root_key
        self.create_standard_key = create_standard_key
        self.import_root_key = import_root_key
        self.import_standard_key = import_standard_key
        self.enforce_token = enforce_token
        self.interval_month = interval_month

    @classmethod
    def from_dict(cls, _dict: Dict) -> "InstancePolicyPropertiesAttributes":
        """Initialize a InstancePolicyPropertiesAttributes object from a json dictionary."""
        args = {}
        if (allowed_network := _dict.get("allowed_network")) is not None:
            args["allowed_network"] = allowed_network
        if (allowed_ip := _dict.get("allowed_ip")) is not None:
            args["allowed_ip"] = allowed_ip
        if (create_root_key := _dict.get("create_root_key")) is not None:
            args["create_root_key"] = create_root_key
        if (create_standard_key := _dict.get("create_standard_key")) is not None:
            args["create_standard_key"] = create_standard_key
        if (import_root_key := _dict.get("import_root_key")) is not None:
            args["import_root_key"] = import_root_key
        if (import_standard_key := _dict.get("import_standard_key")) is not None:
            args["import_standard_key"] = import_standard_key
        if (enforce_token := _dict.get("enforce_token")) is not None:
            args["enforce_token"] = enforce_token
        if (interval_month := _dict.get("interval_month")) is not None:
            args["interval_month"] = interval_month
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a InstancePolicyPropertiesAttributes object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "allowed_network") and self.allowed_network is not None:
            _dict["allowed_network"] = self.allowed_network
        if hasattr(self, "allowed_ip") and self.allowed_ip is not None:
            _dict["allowed_ip"] = self.allowed_ip
        if hasattr(self, "create_root_key") and self.create_root_key is not None:
            _dict["create_root_key"] = self.create_root_key
        if (
            hasattr(self, "create_standard_key")
            and self.create_standard_key is not None
        ):
            _dict["create_standard_key"] = self.create_standard_key
        if hasattr(self, "import_root_key") and self.import_root_key is not None:
            _dict["import_root_key"] = self.import_root_key
        if (
            hasattr(self, "import_standard_key")
            and self.import_standard_key is not None
        ):
            _dict["import_standard_key"] = self.import_standard_key
        if hasattr(self, "enforce_token") and self.enforce_token is not None:
            _dict["enforce_token"] = self.enforce_token
        if hasattr(self, "interval_month") and self.interval_month is not None:
            _dict["interval_month"] = self.interval_month
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this InstancePolicyPropertiesAttributes object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "InstancePolicyPropertiesAttributes") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "InstancePolicyPropertiesAttributes") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class AllowedNetworkEnum(str, Enum):
        """
        If set to `public-and-private`, Key Protect allows the instance to be accessible
        through public and private endpoints. If set to `private-only`, Key Protect
        restricts the instance to only be accessible through a private endpoint.
        """

        PUBLIC_AND_PRIVATE = "public-and-private"
        PRIVATE_ONLY = "private-only"


class InstancePolicyResource:
    """
    InstancePolicyResource.

    :param datetime creation_date: (optional) The date the policy was created. The
          date format follows RFC 3339.
    :param str created_by: (optional) The unique identifier for the resource that
          created the policy.
    :param str updated_by: (optional) The unique identifier for the resource that
          updated the policy.
    :param datetime last_updated: (optional) Updates when the policy is replaced or
          modified. The date format follows RFC 3339.
    :param str policy_type: The type of policy to be retrieved.
    :param InstancePolicyProperties policy_data: User defined metadata that is
          associated with any instance policy.
    """

    def __init__(
        self,
        policy_type: str,
        policy_data: "InstancePolicyProperties",
        *,
        creation_date: Optional[datetime] = None,
        created_by: Optional[str] = None,
        updated_by: Optional[str] = None,
        last_updated: Optional[datetime] = None,
    ) -> None:
        """
        Initialize a InstancePolicyResource object.

        :param str policy_type: The type of policy to be retrieved.
        :param InstancePolicyProperties policy_data: User defined metadata that is
               associated with any instance policy.
        """
        self.creation_date = creation_date
        self.created_by = created_by
        self.updated_by = updated_by
        self.last_updated = last_updated
        self.policy_type = policy_type
        self.policy_data = policy_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> "InstancePolicyResource":
        """Initialize a InstancePolicyResource object from a json dictionary."""
        args = {}
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (created_by := _dict.get("createdBy")) is not None:
            args["created_by"] = created_by
        if (updated_by := _dict.get("updatedBy")) is not None:
            args["updated_by"] = updated_by
        if (last_updated := _dict.get("lastUpdated")) is not None:
            args["last_updated"] = string_to_datetime(last_updated)
        if (policy_type := _dict.get("policy_type")) is not None:
            args["policy_type"] = policy_type
        else:
            raise ValueError(
                "Required property 'policy_type' not present in InstancePolicyResource JSON"
            )
        if (policy_data := _dict.get("policy_data")) is not None:
            args["policy_data"] = InstancePolicyProperties.from_dict(policy_data)
        else:
            args["policy_data"] = None
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a InstancePolicyResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        if hasattr(self, "created_by") and getattr(self, "created_by") is not None:
            _dict["createdBy"] = getattr(self, "created_by")
        if hasattr(self, "updated_by") and getattr(self, "updated_by") is not None:
            _dict["updatedBy"] = getattr(self, "updated_by")
        if hasattr(self, "last_updated") and getattr(self, "last_updated") is not None:
            _dict["lastUpdated"] = datetime_to_string(getattr(self, "last_updated"))
        if hasattr(self, "policy_type") and self.policy_type is not None:
            _dict["policy_type"] = self.policy_type
        if hasattr(self, "policy_data") and self.policy_data is not None:
            if isinstance(self.policy_data, dict):
                _dict["policy_data"] = self.policy_data
            else:
                _dict["policy_data"] = self.policy_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this InstancePolicyResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "InstancePolicyResource") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "InstancePolicyResource") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class InstancePolicyRotationPolicyData:
    """
    User defined metadata that is associated with the `rotation` instance policy type.

    :param bool enabled: If set to `true`, Key Protect enables the specified policy
          for your service instance. If set to `false`, Key Protect disables the specified
          policy for your service instance, and the policy will no longer affect Key
          Protect actions.
          **Note:** If a policy with attributes is disabled, all attributes are reset and
          are not retained.
    :param InstancePolicyRotationPolicyDataAttributes attributes: (optional)
          Attributes of a `rotation` instance policy. Must be provided if the `enabled`
          field is `true`. Cannot be provided if the `enabled` field is `false`.
    """

    def __init__(
        self,
        enabled: bool,
        *,
        attributes: Optional["InstancePolicyRotationPolicyDataAttributes"] = None,
    ) -> None:
        """
        Initialize a InstancePolicyRotationPolicyData object.

        :param bool enabled: If set to `true`, Key Protect enables the specified
               policy for your service instance. If set to `false`, Key Protect disables
               the specified policy for your service instance, and the policy will no
               longer affect Key Protect actions.
               **Note:** If a policy with attributes is disabled, all attributes are reset
               and are not retained.
        :param InstancePolicyRotationPolicyDataAttributes attributes: (optional)
               Attributes of a `rotation` instance policy. Must be provided if the
               `enabled` field is `true`. Cannot be provided if the `enabled` field is
               `false`.
        """
        self.enabled = enabled
        self.attributes = attributes

    @classmethod
    def from_dict(cls, _dict: Dict) -> "InstancePolicyRotationPolicyData":
        """Initialize a InstancePolicyRotationPolicyData object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            args["enabled"] = None
        if (attributes := _dict.get("attributes")) is not None:
            args["attributes"] = InstancePolicyRotationPolicyDataAttributes.from_dict(
                attributes
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a InstancePolicyRotationPolicyData object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        if hasattr(self, "attributes") and self.attributes is not None:
            if isinstance(self.attributes, dict):
                _dict["attributes"] = self.attributes
            else:
                _dict["attributes"] = self.attributes.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this InstancePolicyRotationPolicyData object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "InstancePolicyRotationPolicyData") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "InstancePolicyRotationPolicyData") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class InstancePolicyRotationPolicyDataAttributes:
    """
    Attributes of a `rotation` instance policy. Must be provided if the `enabled` field is
    `true`. Cannot be provided if the `enabled` field is `false`.

    :param int interval_month: (optional) Specifies the key rotation time interval
          in approximate months, where a month is equivalent to 30 days. A minimum of 1
          and a maximum of 12 can be set.
    """

    def __init__(
        self,
        *,
        interval_month: Optional[int] = None,
    ) -> None:
        """
        Initialize a InstancePolicyRotationPolicyDataAttributes object.

        :param int interval_month: (optional) Specifies the key rotation time
               interval in approximate months, where a month is equivalent to 30 days. A
               minimum of 1 and a maximum of 12 can be set.
        """
        self.interval_month = interval_month

    @classmethod
    def from_dict(cls, _dict: Dict) -> "InstancePolicyRotationPolicyDataAttributes":
        """Initialize a InstancePolicyRotationPolicyDataAttributes object from a json dictionary."""
        args = {}
        if (interval_month := _dict.get("interval_month")) is not None:
            args["interval_month"] = interval_month
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a InstancePolicyRotationPolicyDataAttributes object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "interval_month") and self.interval_month is not None:
            _dict["interval_month"] = self.interval_month
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this InstancePolicyRotationPolicyDataAttributes object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "InstancePolicyRotationPolicyDataAttributes") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "InstancePolicyRotationPolicyDataAttributes") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KMIPAdapter:
    """
    Properties applicable to all KMIP adapter resources.

    :param str id: The v4 UUID that uniquely identifies this KMIP adapter.
    :param str name: A human-readable name of the KMIP adapter unique within the kms
          instance. If one is not specified, one will be autogenerated of the format
          `kmip_adapter_<random_string>`. To protect your privacy do not use personal
          data, such as your name or location, as a name for your KMIP adapter. The name
          must be alphanumeric and cannot contain spaces or special characters other than
          `-` or `_`. The name cannot be a UUID.
    :param datetime created_at: The date the KMIP adapter was created. The date
          format follows RFC 3339.
    :param str created_by: The unique identifier of the user that created the KMIP
          adapter.
    :param datetime updated_at: The date the KMIP adapter was last modified, either
          by creation or by modification of adapter subresources. The date format follows
          RFC 3339.
    :param str updated_by: The unique identifier of the user that updated the KMIP
          adapter.
    :param str profile: The profile of KMIP adapter.
    :param str description: (optional) The optional description of the KMIP adapter.
          The maximum length is 240 characters. To protect your privacy, do not use
          personal data, such as your name or location, as a description for your KMIP
          adapter.
    :param KMIPProfileDataBody profile_data: (optional) The data specific to the
          KMIP Adapter profile. This is a required field for profile `native_1.0`.
    """

    def __init__(
        self,
        id: str,
        name: str,
        created_at: datetime,
        created_by: str,
        updated_at: datetime,
        updated_by: str,
        profile: str,
        *,
        description: Optional[str] = None,
        profile_data: Optional["KMIPProfileDataBody"] = None,
    ) -> None:
        """
        Initialize a KMIPAdapter object.

        :param str id: The v4 UUID that uniquely identifies this KMIP adapter.
        :param str name: A human-readable name of the KMIP adapter unique within
               the kms instance. If one is not specified, one will be autogenerated of the
               format `kmip_adapter_<random_string>`. To protect your privacy do not use
               personal data, such as your name or location, as a name for your KMIP
               adapter. The name must be alphanumeric and cannot contain spaces or special
               characters other than `-` or `_`. The name cannot be a UUID.
        :param datetime created_at: The date the KMIP adapter was created. The date
               format follows RFC 3339.
        :param str created_by: The unique identifier of the user that created the
               KMIP adapter.
        :param datetime updated_at: The date the KMIP adapter was last modified,
               either by creation or by modification of adapter subresources. The date
               format follows RFC 3339.
        :param str updated_by: The unique identifier of the user that updated the
               KMIP adapter.
        :param str profile: The profile of KMIP adapter.
        :param str description: (optional) The optional description of the KMIP
               adapter. The maximum length is 240 characters. To protect your privacy, do
               not use personal data, such as your name or location, as a description for
               your KMIP adapter.
        :param KMIPProfileDataBody profile_data: (optional) The data specific to
               the KMIP Adapter profile. This is a required field for profile
               `native_1.0`.
        """
        self.id = id
        self.name = name
        self.created_at = created_at
        self.created_by = created_by
        self.updated_at = updated_at
        self.updated_by = updated_by
        self.profile = profile
        self.description = description
        self.profile_data = profile_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KMIPAdapter":
        """Initialize a KMIPAdapter object from a json dictionary."""
        args = {}
        if (id := _dict.get("id")) is not None:
            args["id"] = id
        else:
            raise ValueError("Required property 'id' not present in KMIPAdapter JSON")
        if (name := _dict.get("name")) is not None:
            args["name"] = name
        else:
            raise ValueError("Required property 'name' not present in KMIPAdapter JSON")
        if (created_at := _dict.get("created_at")) is not None:
            args["created_at"] = string_to_datetime(created_at)
        else:
            args["created_at"] = None
        if (created_by := _dict.get("created_by")) is not None:
            args["created_by"] = created_by
        else:
            raise ValueError(
                "Required property 'created_by' not present in KMIPAdapter JSON"
            )
        if (updated_at := _dict.get("updated_at")) is not None:
            args["updated_at"] = string_to_datetime(updated_at)
        else:
            args["updated_at"] = None
        if (updated_by := _dict.get("updated_by")) is not None:
            args["updated_by"] = updated_by
        else:
            raise ValueError(
                "Required property 'updated_by' not present in KMIPAdapter JSON"
            )
        if (profile := _dict.get("profile")) is not None:
            args["profile"] = profile
        else:
            raise ValueError(
                "Required property 'profile' not present in KMIPAdapter JSON"
            )
        if (description := _dict.get("description")) is not None:
            args["description"] = description
        if (profile_data := _dict.get("profile_data")) is not None:
            args["profile_data"] = profile_data
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KMIPAdapter object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "id") and self.id is not None:
            _dict["id"] = self.id
        if hasattr(self, "name") and self.name is not None:
            _dict["name"] = self.name
        if hasattr(self, "created_at") and self.created_at is not None:
            _dict["created_at"] = datetime_to_string(self.created_at)
        if hasattr(self, "created_by") and self.created_by is not None:
            _dict["created_by"] = self.created_by
        if hasattr(self, "updated_at") and self.updated_at is not None:
            _dict["updated_at"] = datetime_to_string(self.updated_at)
        if hasattr(self, "updated_by") and self.updated_by is not None:
            _dict["updated_by"] = self.updated_by
        if hasattr(self, "profile") and self.profile is not None:
            _dict["profile"] = self.profile
        if hasattr(self, "description") and self.description is not None:
            _dict["description"] = self.description
        if hasattr(self, "profile_data") and self.profile_data is not None:
            if isinstance(self.profile_data, dict):
                _dict["profile_data"] = self.profile_data
            else:
                _dict["profile_data"] = self.profile_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KMIPAdapter object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KMIPAdapter") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KMIPAdapter") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class ProfileEnum(str, Enum):
        """
        The profile of KMIP adapter.
        """

        NATIVE_1_0 = "native_1.0"


class KMIPClientCertificate:
    """
    Properties of a client certificate.

    :param str name: A human-readable name that uniquely identifies a certificate
          within the given adapter. If one is not specified, one will be autogenerated of
          the format `kmip_cert_<random_string>`. To protect your privacy do not use
          personal data, such as your name or location, as a name for your client
          certificate. The name must be alphanumeric and cannot contain spaces or special
          characters other than `-` or `_`. The name cannot be a UUID.
    :param str id: The v4 UUID that uniquely identifies this certificate resource.
    :param datetime created_at: The date this certificate resource was created on
          the KMIP Adapter. The date format follows RFC 3339.
    :param str created_by: The IAM id that created the certificate resource.
    :param str certificate: The client certificate to be associated with the KMIP
          Adapter. It should explicitly have the BEGIN CERTIFICATE and END CERTIFICATE
          tags.
    """

    def __init__(
        self,
        name: str,
        id: str,
        created_at: datetime,
        created_by: str,
        certificate: str,
    ) -> None:
        """
        Initialize a KMIPClientCertificate object.

        :param str name: A human-readable name that uniquely identifies a
               certificate within the given adapter. If one is not specified, one will be
               autogenerated of the format `kmip_cert_<random_string>`. To protect your
               privacy do not use personal data, such as your name or location, as a name
               for your client certificate. The name must be alphanumeric and cannot
               contain spaces or special characters other than `-` or `_`. The name cannot
               be a UUID.
        :param str id: The v4 UUID that uniquely identifies this certificate
               resource.
        :param datetime created_at: The date this certificate resource was created
               on the KMIP Adapter. The date format follows RFC 3339.
        :param str created_by: The IAM id that created the certificate resource.
        :param str certificate: The client certificate to be associated with the
               KMIP Adapter. It should explicitly have the BEGIN CERTIFICATE and END
               CERTIFICATE tags.
        """
        self.name = name
        self.id = id
        self.created_at = created_at
        self.created_by = created_by
        self.certificate = certificate

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KMIPClientCertificate":
        """Initialize a KMIPClientCertificate object from a json dictionary."""
        args = {}
        if (name := _dict.get("name")) is not None:
            args["name"] = name
        else:
            raise ValueError(
                "Required property 'name' not present in KMIPClientCertificate JSON"
            )
        if (id := _dict.get("id")) is not None:
            args["id"] = id
        else:
            raise ValueError(
                "Required property 'id' not present in KMIPClientCertificate JSON"
            )
        if (created_at := _dict.get("created_at")) is not None:
            args["created_at"] = string_to_datetime(created_at)
        else:
            args["created_at"] = None
        if (created_by := _dict.get("created_by")) is not None:
            args["created_by"] = created_by
        else:
            raise ValueError(
                "Required property 'created_by' not present in KMIPClientCertificate JSON"
            )
        if (certificate := _dict.get("certificate")) is not None:
            args["certificate"] = certificate
        else:
            raise ValueError(
                "Required property 'certificate' not present in KMIPClientCertificate JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KMIPClientCertificate object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "name") and self.name is not None:
            _dict["name"] = self.name
        if hasattr(self, "id") and self.id is not None:
            _dict["id"] = self.id
        if hasattr(self, "created_at") and self.created_at is not None:
            _dict["created_at"] = datetime_to_string(self.created_at)
        if hasattr(self, "created_by") and self.created_by is not None:
            _dict["created_by"] = self.created_by
        if hasattr(self, "certificate") and self.certificate is not None:
            _dict["certificate"] = self.certificate
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KMIPClientCertificate object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KMIPClientCertificate") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KMIPClientCertificate") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KMIPClientPartialCertificate:
    """
    Partial properties of a client certificate.

    :param str name: A human-readable name that uniquely identifies a certificate
          within the given adapter. If one is not specified, one will be autogenerated of
          the format `kmip_cert_<random_string>`. To protect your privacy do not use
          personal data, such as your name or location, as a name for your client
          certificate. The name must be alphanumeric and cannot contain spaces or special
          characters other than `-` or `_`. The name cannot be a UUID.
    :param str id: The v4 UUID that uniquely identifies this certificate resource.
    :param datetime created_at: The date this certificate resource was created on
          the KMIP Adapter. The date format follows RFC 3339.
    :param str created_by: The IAM id that created the certificate resource.
    """

    def __init__(
        self,
        name: str,
        id: str,
        created_at: datetime,
        created_by: str,
    ) -> None:
        """
        Initialize a KMIPClientPartialCertificate object.

        :param str name: A human-readable name that uniquely identifies a
               certificate within the given adapter. If one is not specified, one will be
               autogenerated of the format `kmip_cert_<random_string>`. To protect your
               privacy do not use personal data, such as your name or location, as a name
               for your client certificate. The name must be alphanumeric and cannot
               contain spaces or special characters other than `-` or `_`. The name cannot
               be a UUID.
        :param str id: The v4 UUID that uniquely identifies this certificate
               resource.
        :param datetime created_at: The date this certificate resource was created
               on the KMIP Adapter. The date format follows RFC 3339.
        :param str created_by: The IAM id that created the certificate resource.
        """
        self.name = name
        self.id = id
        self.created_at = created_at
        self.created_by = created_by

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KMIPClientPartialCertificate":
        """Initialize a KMIPClientPartialCertificate object from a json dictionary."""
        args = {}
        if (name := _dict.get("name")) is not None:
            args["name"] = name
        else:
            raise ValueError(
                "Required property 'name' not present in KMIPClientPartialCertificate JSON"
            )
        if (id := _dict.get("id")) is not None:
            args["id"] = id
        else:
            raise ValueError(
                "Required property 'id' not present in KMIPClientPartialCertificate JSON"
            )
        if (created_at := _dict.get("created_at")) is not None:
            args["created_at"] = string_to_datetime(created_at)
        else:
            args["created_at"] = None
        if (created_by := _dict.get("created_by")) is not None:
            args["created_by"] = created_by
        else:
            raise ValueError(
                "Required property 'created_by' not present in KMIPClientPartialCertificate JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KMIPClientPartialCertificate object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "name") and self.name is not None:
            _dict["name"] = self.name
        if hasattr(self, "id") and self.id is not None:
            _dict["id"] = self.id
        if hasattr(self, "created_at") and self.created_at is not None:
            _dict["created_at"] = datetime_to_string(self.created_at)
        if hasattr(self, "created_by") and self.created_by is not None:
            _dict["created_by"] = self.created_by
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KMIPClientPartialCertificate object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KMIPClientPartialCertificate") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KMIPClientPartialCertificate") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KMIPObject:
    """
    Properties applicable to all KMIP object resources.

    :param str id: The v4 UUID that uniquely identifies this KMIP object.
    :param int kmip_object_type: The object type of the kmip object according to the
          KMIP specification. Currently, only kmip_object_type 2(Symmetric Key) is
          supported. For more info on the KMIP specification and object types, read
          https://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html#_Toc490660932.
    :param int state: (optional) States are integers and correspond to Pre-Active =
          1, Active = 2, Deactivated = 3, Compromised = 4, Destroyed = 5, Destroyed
          Compromised = 6. For more info on the KMIP specification, read
          https://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html.
    :param datetime created_at: The date the KMIP object was created. The date
          format follows RFC 3339.
    :param str created_by_kmip_client_cert_id: The v4 UUID that uniquely identifies
          the certificate used to create this KMIP object.
    :param str created_by: (optional) The IAM id that created the certificate
          resource used to create this KMIP object.
    :param datetime updated_at: (optional) The date the KMIP object was last
          modified. The date format follows RFC 3339.
    :param str updated_by_kmip_client_cert_id: (optional) The v4 UUID that uniquely
          identifies the certificate used to update this KMIP object.
    :param str updated_by: (optional) The IAM id that created the certificate
          resource used to update this KMIP object.
    :param datetime destroyed_at: (optional) The date the KMIP object was destroyed.
          The date format follows RFC 3339.
    :param str destroyed_by_kmip_client_cert_id: (optional) The v4 UUID that
          uniquely identifies the certificate used to destroy this KMIP object.
    :param str destroyed_by: (optional) The IAM id that created the certificate
          resource used to destroy this KMIP object.
    :param bool recoverable: (optional) A boolean that specifies if the object has
          the ability to be restored.
    """

    def __init__(
        self,
        id: str,
        kmip_object_type: int,
        created_at: datetime,
        created_by_kmip_client_cert_id: str,
        *,
        state: Optional[int] = None,
        created_by: Optional[str] = None,
        updated_at: Optional[datetime] = None,
        updated_by_kmip_client_cert_id: Optional[str] = None,
        updated_by: Optional[str] = None,
        destroyed_at: Optional[datetime] = None,
        destroyed_by_kmip_client_cert_id: Optional[str] = None,
        destroyed_by: Optional[str] = None,
        recoverable: Optional[bool] = None,
    ) -> None:
        """
        Initialize a KMIPObject object.

        :param str id: The v4 UUID that uniquely identifies this KMIP object.
        :param int kmip_object_type: The object type of the kmip object according
               to the KMIP specification. Currently, only kmip_object_type 2(Symmetric
               Key) is supported. For more info on the KMIP specification and object
               types, read
               https://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html#_Toc490660932.
        :param datetime created_at: The date the KMIP object was created. The date
               format follows RFC 3339.
        :param str created_by_kmip_client_cert_id: The v4 UUID that uniquely
               identifies the certificate used to create this KMIP object.
        :param int state: (optional) States are integers and correspond to
               Pre-Active = 1, Active = 2, Deactivated = 3, Compromised = 4, Destroyed =
               5, Destroyed Compromised = 6. For more info on the KMIP specification, read
               https://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html.
        :param str created_by: (optional) The IAM id that created the certificate
               resource used to create this KMIP object.
        :param datetime updated_at: (optional) The date the KMIP object was last
               modified. The date format follows RFC 3339.
        :param str updated_by_kmip_client_cert_id: (optional) The v4 UUID that
               uniquely identifies the certificate used to update this KMIP object.
        :param str updated_by: (optional) The IAM id that created the certificate
               resource used to update this KMIP object.
        :param datetime destroyed_at: (optional) The date the KMIP object was
               destroyed. The date format follows RFC 3339.
        :param str destroyed_by_kmip_client_cert_id: (optional) The v4 UUID that
               uniquely identifies the certificate used to destroy this KMIP object.
        :param str destroyed_by: (optional) The IAM id that created the certificate
               resource used to destroy this KMIP object.
        :param bool recoverable: (optional) A boolean that specifies if the object
               has the ability to be restored.
        """
        self.id = id
        self.kmip_object_type = kmip_object_type
        self.state = state
        self.created_at = created_at
        self.created_by_kmip_client_cert_id = created_by_kmip_client_cert_id
        self.created_by = created_by
        self.updated_at = updated_at
        self.updated_by_kmip_client_cert_id = updated_by_kmip_client_cert_id
        self.updated_by = updated_by
        self.destroyed_at = destroyed_at
        self.destroyed_by_kmip_client_cert_id = destroyed_by_kmip_client_cert_id
        self.destroyed_by = destroyed_by
        self.recoverable = recoverable

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KMIPObject":
        """Initialize a KMIPObject object from a json dictionary."""
        args = {}
        if (id := _dict.get("id")) is not None:
            args["id"] = id
        else:
            raise ValueError("Required property 'id' not present in KMIPObject JSON")
        if (kmip_object_type := _dict.get("kmip_object_type")) is not None:
            args["kmip_object_type"] = kmip_object_type
        else:
            raise ValueError(
                "Required property 'kmip_object_type' not present in KMIPObject JSON"
            )
        if (state := _dict.get("state")) is not None:
            args["state"] = state
        if (created_at := _dict.get("created_at")) is not None:
            args["created_at"] = string_to_datetime(created_at)
        else:
            args["created_at"] = None
        if (
            created_by_kmip_client_cert_id := _dict.get(
                "created_by_kmip_client_cert_id"
            )
        ) is not None:
            args["created_by_kmip_client_cert_id"] = created_by_kmip_client_cert_id
        else:
            raise ValueError(
                "Required property 'created_by_kmip_client_cert_id' not present in KMIPObject JSON"
            )
        if (created_by := _dict.get("created_by")) is not None:
            args["created_by"] = created_by
        if (updated_at := _dict.get("updated_at")) is not None:
            args["updated_at"] = string_to_datetime(updated_at)
        if (
            updated_by_kmip_client_cert_id := _dict.get(
                "updated_by_kmip_client_cert_id"
            )
        ) is not None:
            args["updated_by_kmip_client_cert_id"] = updated_by_kmip_client_cert_id
        if (updated_by := _dict.get("updated_by")) is not None:
            args["updated_by"] = updated_by
        if (destroyed_at := _dict.get("destroyed_at")) is not None:
            args["destroyed_at"] = string_to_datetime(destroyed_at)
        if (
            destroyed_by_kmip_client_cert_id := _dict.get(
                "destroyed_by_kmip_client_cert_id"
            )
        ) is not None:
            args["destroyed_by_kmip_client_cert_id"] = destroyed_by_kmip_client_cert_id
        if (destroyed_by := _dict.get("destroyed_by")) is not None:
            args["destroyed_by"] = destroyed_by
        if (recoverable := _dict.get("recoverable")) is not None:
            args["recoverable"] = recoverable
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KMIPObject object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "id") and self.id is not None:
            _dict["id"] = self.id
        if hasattr(self, "kmip_object_type") and self.kmip_object_type is not None:
            _dict["kmip_object_type"] = self.kmip_object_type
        if hasattr(self, "state") and self.state is not None:
            _dict["state"] = self.state
        if hasattr(self, "created_at") and self.created_at is not None:
            _dict["created_at"] = datetime_to_string(self.created_at)
        if (
            hasattr(self, "created_by_kmip_client_cert_id")
            and self.created_by_kmip_client_cert_id is not None
        ):
            _dict["created_by_kmip_client_cert_id"] = (
                self.created_by_kmip_client_cert_id
            )
        if hasattr(self, "created_by") and self.created_by is not None:
            _dict["created_by"] = self.created_by
        if hasattr(self, "updated_at") and self.updated_at is not None:
            _dict["updated_at"] = datetime_to_string(self.updated_at)
        if (
            hasattr(self, "updated_by_kmip_client_cert_id")
            and self.updated_by_kmip_client_cert_id is not None
        ):
            _dict["updated_by_kmip_client_cert_id"] = (
                self.updated_by_kmip_client_cert_id
            )
        if hasattr(self, "updated_by") and self.updated_by is not None:
            _dict["updated_by"] = self.updated_by
        if hasattr(self, "destroyed_at") and self.destroyed_at is not None:
            _dict["destroyed_at"] = datetime_to_string(self.destroyed_at)
        if (
            hasattr(self, "destroyed_by_kmip_client_cert_id")
            and self.destroyed_by_kmip_client_cert_id is not None
        ):
            _dict["destroyed_by_kmip_client_cert_id"] = (
                self.destroyed_by_kmip_client_cert_id
            )
        if hasattr(self, "destroyed_by") and self.destroyed_by is not None:
            _dict["destroyed_by"] = self.destroyed_by
        if hasattr(self, "recoverable") and self.recoverable is not None:
            _dict["recoverable"] = self.recoverable
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KMIPObject object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KMIPObject") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KMIPObject") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KMIPProfileDataBody:
    """
    The data specific to the KMIP Adapter profile. This is a required field for profile
    `native_1.0`.

    """

    def __init__(
        self,
    ) -> None:
        """
        Initialize a KMIPProfileDataBody object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(["KMIPProfileDataBodyKMIPProfileDataNative"])
        )
        raise Exception(msg)


class Key:
    """
    Properties associated with a key response.

    :param CollectionMetadataOneOf metadata: (optional)
    :param List[KeyWithPayload] resources: (optional) A collection of resources.
    """

    def __init__(
        self,
        *,
        metadata: Optional["CollectionMetadataOneOf"] = None,
        resources: Optional[List["KeyWithPayload"]] = None,
    ) -> None:
        """
        Initialize a Key object.

        :param CollectionMetadataOneOf metadata: (optional)
        :param List[KeyWithPayload] resources: (optional) A collection of
               resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "Key":
        """Initialize a Key object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = metadata
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [KeyWithPayload.from_dict(v) for v in resources]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Key object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Key object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "Key") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "Key") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KeyActionOneOfResponse:
    """
    KeyActionOneOfResponse.

    """

    def __init__(
        self,
    ) -> None:
        """
        Initialize a KeyActionOneOfResponse object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(
                [
                    "KeyActionOneOfResponseWrapKeyResponseBody",
                    "KeyActionOneOfResponseUnwrapKeyResponseBody",
                    "KeyActionOneOfResponseRewrapKeyResponseBody",
                ]
            )
        )
        raise Exception(msg)


class KeyAlias:
    """
    Properties associated with a specific key alias.

    :param CollectionMetadata metadata: (optional) The metadata that describes the
          resource array.
    :param List[KeyAliasResource] resources: (optional) A collection of resources.
    """

    def __init__(
        self,
        *,
        metadata: Optional["CollectionMetadata"] = None,
        resources: Optional[List["KeyAliasResource"]] = None,
    ) -> None:
        """
        Initialize a KeyAlias object.

        :param CollectionMetadata metadata: (optional) The metadata that describes
               the resource array.
        :param List[KeyAliasResource] resources: (optional) A collection of
               resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyAlias":
        """Initialize a KeyAlias object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [KeyAliasResource.from_dict(v) for v in resources]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyAlias object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyAlias object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyAlias") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyAlias") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KeyAliasResource:
    """
    Properties associated with an alias.

    :param str key_id: (optional) The ID that identifies the key that is associated
          with the alias.
    :param str alias: (optional) The unique, human-readable alias assigned to the
          key.
    :param str created_by: (optional) The unique identifier for the user that
          created the alias.
    :param datetime creation_date: (optional) The date the alias was created. The
          date format follows RFC 3339.
    """

    def __init__(
        self,
        *,
        key_id: Optional[str] = None,
        alias: Optional[str] = None,
        created_by: Optional[str] = None,
        creation_date: Optional[datetime] = None,
    ) -> None:
        """
        Initialize a KeyAliasResource object.

        """
        self.key_id = key_id
        self.alias = alias
        self.created_by = created_by
        self.creation_date = creation_date

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyAliasResource":
        """Initialize a KeyAliasResource object from a json dictionary."""
        args = {}
        if (key_id := _dict.get("keyId")) is not None:
            args["key_id"] = key_id
        if (alias := _dict.get("alias")) is not None:
            args["alias"] = alias
        if (created_by := _dict.get("createdBy")) is not None:
            args["created_by"] = created_by
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyAliasResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "key_id") and getattr(self, "key_id") is not None:
            _dict["keyId"] = getattr(self, "key_id")
        if hasattr(self, "alias") and getattr(self, "alias") is not None:
            _dict["alias"] = getattr(self, "alias")
        if hasattr(self, "created_by") and getattr(self, "created_by") is not None:
            _dict["createdBy"] = getattr(self, "created_by")
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyAliasResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyAliasResource") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyAliasResource") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KeyFullRepresentation:
    """
    Properties returned only for DELETE.

    :param str type: (optional) Specifies the MIME type that represents the key
          resource. Currently, only the default is supported.
    :param str id: (optional) The v4 UUID used to uniquely identify the resource, as
          specified by RFC 4122.
    :param str name: (optional) A human-readable name assigned to your key for
          convenience. To protect your privacy do not use personal data, such as your name
          or location, as the name for your key.
    :param List[str] aliases: (optional) One or more, up to a total of five,
          human-readable unique aliases assigned to your key. To protect your privacy do
          not use personal data, such as your name or location, as an alias for your key.
          Each alias must be alphanumeric and cannot contain spaces or special characters
          other than `-` or `_`. The alias cannot be a UUID and must not be a Key Protect
          reserved name: `allowed_ip`, `key`, `keys`, `metadata`, `policy`, `policies`,
          `registration`, `registrations`, `ring`, `rings`, `rotate`, `wrap`, `unwrap`,
          `rewrap`, `version`, `versions`.
    :param str description: (optional) A text field used to provide a more detailed
          description of the key. The maximum length is 240 characters. To protect your
          privacy, do not use personal data, such as your name or location, as a
          description for your key.
    :param List[str] tags: (optional) Up to 30 tags can be created. Tags can be
          between 0-30 characters, including spaces. Special characters not permitted
          include angled brackets, comma, colon, ampersand, and vertical pipe character
          (|). To protect your privacy, do not use personal data, such as your name or
          location, as a tag for your key.
    :param int state: (optional) The key state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :param datetime expiration_date: (optional) The date and time that the key
          expires in the system, in RFC 3339 format (YYYY-MM-DD HH:MM:SS.SS, for example
          2019-10-12T07:20:50.52Z). Keys created with an expiration date automatically
          transition to the Deactivated state within one hour after expiration. In this
          state, the only allowed actions on the key are unwrap, rewrap, rotate, and
          delete. Deactivated keys cannot be used to encrypt (wrap) new data, even if
          rotated while deactivated. Rotation does not reset or extend the expiration
          date, nor does it allow the date to be changed. It is recommended that any data
          encrypted with an expiring or expired key be re-encrypted using a new customer
          root key (CRK) before the original CRK expires, to prevent service disruptions.
          Deleting and restoring a deactivated key does not move it back to the Active
          state. If the expirationDate attribute is omitted, the key does not expire.
    :param bool extractable: (optional) A boolean that determines whether the key
          material can leave the service. If set to `false`, Key Protect designates the
          key as a nonextractable root key used for `wrap` and `unwrap` actions. If set to
          `true`, Key Protect designates the key as a standard key that you can store in
          your apps and services. Once set to `false` it cannot be changed to `true`.
    :param str crn: (optional) The Cloud Resource Name (CRN) that uniquely
          identifies your cloud resources.
    :param bool imported: (optional) A boolean that shows whether your key was
          originally imported or generated in Key Protect. The value is set by Key Protect
          based on how the key material is initially added to the service. A value of
          `true` indicates that you must provide new key material when it's time to rotate
          the key. A value of `false` indicates that Key Protect will generate the new key
          material on a `rotate` operation, as it did in key creation.
    :param str key_ring_id: (optional) An ID that identifies the key ring. Each ID
          is unique only within the given instance and is not reserved across the Key
          Protect service.
    :param datetime creation_date: (optional) The date the key material was created.
          The date format follows RFC 3339.
    :param str created_by: (optional) The unique identifier for the resource that
          created the key.
    :param str algorithm_type: (optional) Deprecated: Deprecated.
    :param KeyFullRepresentationAlgorithmMetadata algorithm_metadata: (optional)
          Deprecated.
    :param int algorithm_bit_size: (optional) Deprecated: Deprecated.
    :param str algorithm_mode: (optional) Deprecated: Deprecated.
    :param int nonactive_state_reason: (optional) A code indicating the reason the
          key is not in the activation state.
    :param datetime last_update_date: (optional) Updates when any part of the key
          metadata is modified. The date format follows RFC 3339.
    :param datetime last_rotate_date: (optional) Updates to show when the key was
          last rotated. The date format follows RFC 3339.
    :param KeyVersion key_version: (optional) Properties associated with a specific
          key version.
    :param DualAuthKeyMetadata dual_auth_delete: (optional) Metadata that indicates
          the status of a dual authorization policy on the key.
    :param RotationKeyMetadata rotation: (optional) Metadata that indicates the
          status of a rotation policy on the key.
    :param bool deleted: (optional) A boolean that determines whether the key has
          been deleted.
    :param datetime deletion_date: (optional) The date the key material was
          destroyed. The date format follows RFC 3339.
    :param str deleted_by: (optional) The unique identifier for the resource that
          deleted the key.
    :param datetime restore_expiration_date: (optional) The date the key will no
          longer have the ability to be restored.
    :param bool restore_allowed: (optional) A boolean that specifies if your key has
          the ability to be restored. A value of `true` indicates that the key can be
          restored. A value of `false` indicates that the key is unable to be restored.
    :param bool purge_allowed: (optional) A boolean that specifies if the key can be
          purged. A value of `true` indicates that the key can be purged. A value of
          `false` indicates that the key is within the purge wait period and is not ready
          to be purged.
    :param datetime purge_allowed_from: (optional) The date the key will be ready to
          be purged.
    :param datetime purge_scheduled_on: (optional) The date the deleted key will be
          automatically purged from Key Protect system.
    """

    def __init__(
        self,
        *,
        type: Optional[str] = None,
        id: Optional[str] = None,
        name: Optional[str] = None,
        aliases: Optional[List[str]] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
        state: Optional[int] = None,
        expiration_date: Optional[datetime] = None,
        extractable: Optional[bool] = None,
        crn: Optional[str] = None,
        imported: Optional[bool] = None,
        key_ring_id: Optional[str] = None,
        creation_date: Optional[datetime] = None,
        created_by: Optional[str] = None,
        algorithm_type: Optional[str] = None,
        algorithm_metadata: Optional["KeyFullRepresentationAlgorithmMetadata"] = None,
        algorithm_bit_size: Optional[int] = None,
        algorithm_mode: Optional[str] = None,
        nonactive_state_reason: Optional[int] = None,
        last_update_date: Optional[datetime] = None,
        last_rotate_date: Optional[datetime] = None,
        key_version: Optional["KeyVersion"] = None,
        dual_auth_delete: Optional["DualAuthKeyMetadata"] = None,
        rotation: Optional["RotationKeyMetadata"] = None,
        deleted: Optional[bool] = None,
        deletion_date: Optional[datetime] = None,
        deleted_by: Optional[str] = None,
        restore_expiration_date: Optional[datetime] = None,
        restore_allowed: Optional[bool] = None,
        purge_allowed: Optional[bool] = None,
        purge_allowed_from: Optional[datetime] = None,
        purge_scheduled_on: Optional[datetime] = None,
    ) -> None:
        """
        Initialize a KeyFullRepresentation object.

        :param str type: (optional) Specifies the MIME type that represents the key
               resource. Currently, only the default is supported.
        :param str name: (optional) A human-readable name assigned to your key for
               convenience. To protect your privacy do not use personal data, such as your
               name or location, as the name for your key.
        :param List[str] aliases: (optional) One or more, up to a total of five,
               human-readable unique aliases assigned to your key. To protect your privacy
               do not use personal data, such as your name or location, as an alias for
               your key. Each alias must be alphanumeric and cannot contain spaces or
               special characters other than `-` or `_`. The alias cannot be a UUID and
               must not be a Key Protect reserved name: `allowed_ip`, `key`, `keys`,
               `metadata`, `policy`, `policies`, `registration`, `registrations`, `ring`,
               `rings`, `rotate`, `wrap`, `unwrap`, `rewrap`, `version`, `versions`.
        :param str description: (optional) A text field used to provide a more
               detailed description of the key. The maximum length is 240 characters. To
               protect your privacy, do not use personal data, such as your name or
               location, as a description for your key.
        :param List[str] tags: (optional) Up to 30 tags can be created. Tags can be
               between 0-30 characters, including spaces. Special characters not permitted
               include angled brackets, comma, colon, ampersand, and vertical pipe
               character (|). To protect your privacy, do not use personal data, such as
               your name or location, as a tag for your key.
        :param bool extractable: (optional) A boolean that determines whether the
               key material can leave the service. If set to `false`, Key Protect
               designates the key as a nonextractable root key used for `wrap` and
               `unwrap` actions. If set to `true`, Key Protect designates the key as a
               standard key that you can store in your apps and services. Once set to
               `false` it cannot be changed to `true`.
        :param str key_ring_id: (optional) An ID that identifies the key ring. Each
               ID is unique only within the given instance and is not reserved across the
               Key Protect service.
        :param int algorithm_bit_size: (optional) Deprecated: Deprecated.
        :param str algorithm_mode: (optional) Deprecated: Deprecated.
        :param DualAuthKeyMetadata dual_auth_delete: (optional) Metadata that
               indicates the status of a dual authorization policy on the key.
        :param RotationKeyMetadata rotation: (optional) Metadata that indicates the
               status of a rotation policy on the key.
        :param datetime restore_expiration_date: (optional) The date the key will
               no longer have the ability to be restored.
        :param bool restore_allowed: (optional) A boolean that specifies if your
               key has the ability to be restored. A value of `true` indicates that the
               key can be restored. A value of `false` indicates that the key is unable to
               be restored.
        :param bool purge_allowed: (optional) A boolean that specifies if the key
               can be purged. A value of `true` indicates that the key can be purged. A
               value of `false` indicates that the key is within the purge wait period and
               is not ready to be purged.
        :param datetime purge_allowed_from: (optional) The date the key will be
               ready to be purged.
        :param datetime purge_scheduled_on: (optional) The date the deleted key
               will be automatically purged from Key Protect system.
        """
        self.type = type
        self.id = id
        self.name = name
        self.aliases = aliases
        self.description = description
        self.tags = tags
        self.state = state
        self.expiration_date = expiration_date
        self.extractable = extractable
        self.crn = crn
        self.imported = imported
        self.key_ring_id = key_ring_id
        self.creation_date = creation_date
        self.created_by = created_by
        self.algorithm_type = algorithm_type
        self.algorithm_metadata = algorithm_metadata
        self.algorithm_bit_size = algorithm_bit_size
        self.algorithm_mode = algorithm_mode
        self.nonactive_state_reason = nonactive_state_reason
        self.last_update_date = last_update_date
        self.last_rotate_date = last_rotate_date
        self.key_version = key_version
        self.dual_auth_delete = dual_auth_delete
        self.rotation = rotation
        self.deleted = deleted
        self.deletion_date = deletion_date
        self.deleted_by = deleted_by
        self.restore_expiration_date = restore_expiration_date
        self.restore_allowed = restore_allowed
        self.purge_allowed = purge_allowed
        self.purge_allowed_from = purge_allowed_from
        self.purge_scheduled_on = purge_scheduled_on

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyFullRepresentation":
        """Initialize a KeyFullRepresentation object from a json dictionary."""
        args = {}
        if (type := _dict.get("type")) is not None:
            args["type"] = type
        if (id := _dict.get("id")) is not None:
            args["id"] = id
        if (name := _dict.get("name")) is not None:
            args["name"] = name
        if (aliases := _dict.get("aliases")) is not None:
            args["aliases"] = aliases
        if (description := _dict.get("description")) is not None:
            args["description"] = description
        if (tags := _dict.get("tags")) is not None:
            args["tags"] = tags
        if (state := _dict.get("state")) is not None:
            args["state"] = state
        if (expiration_date := _dict.get("expirationDate")) is not None:
            args["expiration_date"] = string_to_datetime(expiration_date)
        if (extractable := _dict.get("extractable")) is not None:
            args["extractable"] = extractable
        if (crn := _dict.get("crn")) is not None:
            args["crn"] = crn
        if (imported := _dict.get("imported")) is not None:
            args["imported"] = imported
        if (key_ring_id := _dict.get("keyRingID")) is not None:
            args["key_ring_id"] = key_ring_id
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (created_by := _dict.get("createdBy")) is not None:
            args["created_by"] = created_by
        if (algorithm_type := _dict.get("algorithmType")) is not None:
            args["algorithm_type"] = algorithm_type
        if (algorithm_metadata := _dict.get("algorithmMetadata")) is not None:
            args["algorithm_metadata"] = (
                KeyFullRepresentationAlgorithmMetadata.from_dict(algorithm_metadata)
            )
        if (algorithm_bit_size := _dict.get("algorithmBitSize")) is not None:
            args["algorithm_bit_size"] = algorithm_bit_size
        if (algorithm_mode := _dict.get("algorithmMode")) is not None:
            args["algorithm_mode"] = algorithm_mode
        if (nonactive_state_reason := _dict.get("nonactiveStateReason")) is not None:
            args["nonactive_state_reason"] = nonactive_state_reason
        if (last_update_date := _dict.get("lastUpdateDate")) is not None:
            args["last_update_date"] = string_to_datetime(last_update_date)
        if (last_rotate_date := _dict.get("lastRotateDate")) is not None:
            args["last_rotate_date"] = string_to_datetime(last_rotate_date)
        if (key_version := _dict.get("keyVersion")) is not None:
            args["key_version"] = KeyVersion.from_dict(key_version)
        if (dual_auth_delete := _dict.get("dualAuthDelete")) is not None:
            args["dual_auth_delete"] = DualAuthKeyMetadata.from_dict(dual_auth_delete)
        if (rotation := _dict.get("rotation")) is not None:
            args["rotation"] = RotationKeyMetadata.from_dict(rotation)
        if (deleted := _dict.get("deleted")) is not None:
            args["deleted"] = deleted
        if (deletion_date := _dict.get("deletionDate")) is not None:
            args["deletion_date"] = string_to_datetime(deletion_date)
        if (deleted_by := _dict.get("deletedBy")) is not None:
            args["deleted_by"] = deleted_by
        if (restore_expiration_date := _dict.get("restoreExpirationDate")) is not None:
            args["restore_expiration_date"] = string_to_datetime(
                restore_expiration_date
            )
        if (restore_allowed := _dict.get("restoreAllowed")) is not None:
            args["restore_allowed"] = restore_allowed
        if (purge_allowed := _dict.get("purgeAllowed")) is not None:
            args["purge_allowed"] = purge_allowed
        if (purge_allowed_from := _dict.get("purgeAllowedFrom")) is not None:
            args["purge_allowed_from"] = string_to_datetime(purge_allowed_from)
        if (purge_scheduled_on := _dict.get("purgeScheduledOn")) is not None:
            args["purge_scheduled_on"] = string_to_datetime(purge_scheduled_on)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyFullRepresentation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "type") and self.type is not None:
            _dict["type"] = self.type
        if hasattr(self, "id") and getattr(self, "id") is not None:
            _dict["id"] = getattr(self, "id")
        if hasattr(self, "name") and self.name is not None:
            _dict["name"] = self.name
        if hasattr(self, "aliases") and self.aliases is not None:
            _dict["aliases"] = self.aliases
        if hasattr(self, "description") and self.description is not None:
            _dict["description"] = self.description
        if hasattr(self, "tags") and self.tags is not None:
            _dict["tags"] = self.tags
        if hasattr(self, "state") and getattr(self, "state") is not None:
            _dict["state"] = getattr(self, "state")
        if (
            hasattr(self, "expiration_date")
            and getattr(self, "expiration_date") is not None
        ):
            _dict["expirationDate"] = datetime_to_string(
                getattr(self, "expiration_date")
            )
        if hasattr(self, "extractable") and self.extractable is not None:
            _dict["extractable"] = self.extractable
        if hasattr(self, "crn") and getattr(self, "crn") is not None:
            _dict["crn"] = getattr(self, "crn")
        if hasattr(self, "imported") and getattr(self, "imported") is not None:
            _dict["imported"] = getattr(self, "imported")
        if hasattr(self, "key_ring_id") and self.key_ring_id is not None:
            _dict["keyRingID"] = self.key_ring_id
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        if hasattr(self, "created_by") and getattr(self, "created_by") is not None:
            _dict["createdBy"] = getattr(self, "created_by")
        if (
            hasattr(self, "algorithm_type")
            and getattr(self, "algorithm_type") is not None
        ):
            _dict["algorithmType"] = getattr(self, "algorithm_type")
        if (
            hasattr(self, "algorithm_metadata")
            and getattr(self, "algorithm_metadata") is not None
        ):
            if isinstance(getattr(self, "algorithm_metadata"), dict):
                _dict["algorithmMetadata"] = getattr(self, "algorithm_metadata")
            else:
                _dict["algorithmMetadata"] = getattr(
                    self, "algorithm_metadata"
                ).to_dict()
        if hasattr(self, "algorithm_bit_size") and self.algorithm_bit_size is not None:
            _dict["algorithmBitSize"] = self.algorithm_bit_size
        if hasattr(self, "algorithm_mode") and self.algorithm_mode is not None:
            _dict["algorithmMode"] = self.algorithm_mode
        if (
            hasattr(self, "nonactive_state_reason")
            and getattr(self, "nonactive_state_reason") is not None
        ):
            _dict["nonactiveStateReason"] = getattr(self, "nonactive_state_reason")
        if (
            hasattr(self, "last_update_date")
            and getattr(self, "last_update_date") is not None
        ):
            _dict["lastUpdateDate"] = datetime_to_string(
                getattr(self, "last_update_date")
            )
        if (
            hasattr(self, "last_rotate_date")
            and getattr(self, "last_rotate_date") is not None
        ):
            _dict["lastRotateDate"] = datetime_to_string(
                getattr(self, "last_rotate_date")
            )
        if hasattr(self, "key_version") and getattr(self, "key_version") is not None:
            if isinstance(getattr(self, "key_version"), dict):
                _dict["keyVersion"] = getattr(self, "key_version")
            else:
                _dict["keyVersion"] = getattr(self, "key_version").to_dict()
        if hasattr(self, "dual_auth_delete") and self.dual_auth_delete is not None:
            if isinstance(self.dual_auth_delete, dict):
                _dict["dualAuthDelete"] = self.dual_auth_delete
            else:
                _dict["dualAuthDelete"] = self.dual_auth_delete.to_dict()
        if hasattr(self, "rotation") and self.rotation is not None:
            if isinstance(self.rotation, dict):
                _dict["rotation"] = self.rotation
            else:
                _dict["rotation"] = self.rotation.to_dict()
        if hasattr(self, "deleted") and getattr(self, "deleted") is not None:
            _dict["deleted"] = getattr(self, "deleted")
        if (
            hasattr(self, "deletion_date")
            and getattr(self, "deletion_date") is not None
        ):
            _dict["deletionDate"] = datetime_to_string(getattr(self, "deletion_date"))
        if hasattr(self, "deleted_by") and getattr(self, "deleted_by") is not None:
            _dict["deletedBy"] = getattr(self, "deleted_by")
        if (
            hasattr(self, "restore_expiration_date")
            and self.restore_expiration_date is not None
        ):
            _dict["restoreExpirationDate"] = datetime_to_string(
                self.restore_expiration_date
            )
        if hasattr(self, "restore_allowed") and self.restore_allowed is not None:
            _dict["restoreAllowed"] = self.restore_allowed
        if hasattr(self, "purge_allowed") and self.purge_allowed is not None:
            _dict["purgeAllowed"] = self.purge_allowed
        if hasattr(self, "purge_allowed_from") and self.purge_allowed_from is not None:
            _dict["purgeAllowedFrom"] = datetime_to_string(self.purge_allowed_from)
        if hasattr(self, "purge_scheduled_on") and self.purge_scheduled_on is not None:
            _dict["purgeScheduledOn"] = datetime_to_string(self.purge_scheduled_on)
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyFullRepresentation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyFullRepresentation") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyFullRepresentation") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        Specifies the MIME type that represents the key resource. Currently, only the
        default is supported.
        """

        APPLICATION_VND_IBM_KMS_KEY_JSON = "application/vnd.ibm.kms.key+json"

    class AlgorithmTypeEnum(str, Enum):
        """
        Deprecated.
        """

        AES = "AES"
        DEPRECATED = "Deprecated"

    class AlgorithmModeEnum(str, Enum):
        """
        Deprecated.
        """

        CBC_PAD = "CBC_PAD"
        DEPRECATED = "Deprecated"


class KeyFullRepresentationAlgorithmMetadata:
    """
    Deprecated.

    :param str bit_length: (optional) Deprecated.
    :param str mode: (optional) Deprecated.
    """

    def __init__(
        self,
        *,
        bit_length: Optional[str] = None,
        mode: Optional[str] = None,
    ) -> None:
        """
        Initialize a KeyFullRepresentationAlgorithmMetadata object.

        :param str bit_length: (optional) Deprecated.
        :param str mode: (optional) Deprecated.
        """
        self.bit_length = bit_length
        self.mode = mode

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyFullRepresentationAlgorithmMetadata":
        """Initialize a KeyFullRepresentationAlgorithmMetadata object from a json dictionary."""
        args = {}
        if (bit_length := _dict.get("bitLength")) is not None:
            args["bit_length"] = bit_length
        if (mode := _dict.get("mode")) is not None:
            args["mode"] = mode
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyFullRepresentationAlgorithmMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "bit_length") and self.bit_length is not None:
            _dict["bitLength"] = self.bit_length
        if hasattr(self, "mode") and self.mode is not None:
            _dict["mode"] = self.mode
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyFullRepresentationAlgorithmMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyFullRepresentationAlgorithmMetadata") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyFullRepresentationAlgorithmMetadata") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class ModeEnum(str, Enum):
        """
        Deprecated.
        """

        CBC_PAD = "CBC_PAD"
        DEPRECATED = "Deprecated"


class KeyPolicyDualAuthDelete:
    """
    Properties that are associated with key level dual authorization delete policy.

    :param str type: Specifies the MIME type that represents the policy resource.
          Currently, only the default is supported.
    :param KeyPolicyDualAuthDeleteDualAuthDelete dual_auth_delete: Data associated
          with the dual authorization delete policy.
    """

    def __init__(
        self,
        type: str,
        dual_auth_delete: "KeyPolicyDualAuthDeleteDualAuthDelete",
    ) -> None:
        """
        Initialize a KeyPolicyDualAuthDelete object.

        :param str type: Specifies the MIME type that represents the policy
               resource. Currently, only the default is supported.
        :param KeyPolicyDualAuthDeleteDualAuthDelete dual_auth_delete: Data
               associated with the dual authorization delete policy.
        """
        self.type = type
        self.dual_auth_delete = dual_auth_delete

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyPolicyDualAuthDelete":
        """Initialize a KeyPolicyDualAuthDelete object from a json dictionary."""
        args = {}
        if (type := _dict.get("type")) is not None:
            args["type"] = type
        else:
            raise ValueError(
                "Required property 'type' not present in KeyPolicyDualAuthDelete JSON"
            )
        if (dual_auth_delete := _dict.get("dualAuthDelete")) is not None:
            args["dual_auth_delete"] = KeyPolicyDualAuthDeleteDualAuthDelete.from_dict(
                dual_auth_delete
            )
        else:
            args["dual_auth_delete"] = None
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyPolicyDualAuthDelete object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "type") and self.type is not None:
            _dict["type"] = self.type
        if hasattr(self, "dual_auth_delete") and self.dual_auth_delete is not None:
            if isinstance(self.dual_auth_delete, dict):
                _dict["dualAuthDelete"] = self.dual_auth_delete
            else:
                _dict["dualAuthDelete"] = self.dual_auth_delete.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyPolicyDualAuthDelete object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyPolicyDualAuthDelete") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyPolicyDualAuthDelete") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        Specifies the MIME type that represents the policy resource. Currently, only the
        default is supported.
        """

        APPLICATION_VND_IBM_KMS_POLICY_JSON = "application/vnd.ibm.kms.policy+json"


class KeyPolicyDualAuthDeleteDualAuthDelete:
    """
    Data associated with the dual authorization delete policy.

    :param bool enabled: If set to `true`, Key Protect enables a dual authorization
          policy on a single key. After you enable the policy, Key Protect requires an
          authorization from two users to delete this key. For example, you can authorize
          the deletion first by using the [SetKeyForDeletion](#invoke-an-action-on-a-key)
          action. Then, a different user provides a second authorization implicitly by
          calling `DELETE /keys` to delete the key.
          **Note:** Once the dual authorization policy is set on the key, it cannot be
          reverted.
    """

    def __init__(
        self,
        enabled: bool,
    ) -> None:
        """
        Initialize a KeyPolicyDualAuthDeleteDualAuthDelete object.

        :param bool enabled: If set to `true`, Key Protect enables a dual
               authorization policy on a single key. After you enable the policy, Key
               Protect requires an authorization from two users to delete this key. For
               example, you can authorize the deletion first by using the
               [SetKeyForDeletion](#invoke-an-action-on-a-key) action. Then, a different
               user provides a second authorization implicitly by calling `DELETE /keys`
               to delete the key.
               **Note:** Once the dual authorization policy is set on the key, it cannot
               be reverted.
        """
        self.enabled = enabled

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyPolicyDualAuthDeleteDualAuthDelete":
        """Initialize a KeyPolicyDualAuthDeleteDualAuthDelete object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            args["enabled"] = None
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyPolicyDualAuthDeleteDualAuthDelete object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyPolicyDualAuthDeleteDualAuthDelete object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyPolicyDualAuthDeleteDualAuthDelete") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyPolicyDualAuthDeleteDualAuthDelete") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KeyPolicyRotation:
    """
    KeyPolicyRotation.

    :param str type: Specifies the MIME type that represents the policy resource.
          Currently, only the default is supported.
    :param KeyPolicyRotationRotation rotation: Data associated with the automatic
          key rotation policy.
    """

    def __init__(
        self,
        type: str,
        rotation: "KeyPolicyRotationRotation",
    ) -> None:
        """
        Initialize a KeyPolicyRotation object.

        :param str type: Specifies the MIME type that represents the policy
               resource. Currently, only the default is supported.
        :param KeyPolicyRotationRotation rotation: Data associated with the
               automatic key rotation policy.
        """
        self.type = type
        self.rotation = rotation

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyPolicyRotation":
        """Initialize a KeyPolicyRotation object from a json dictionary."""
        args = {}
        if (type := _dict.get("type")) is not None:
            args["type"] = type
        else:
            raise ValueError(
                "Required property 'type' not present in KeyPolicyRotation JSON"
            )
        if (rotation := _dict.get("rotation")) is not None:
            args["rotation"] = KeyPolicyRotationRotation.from_dict(rotation)
        else:
            args["rotation"] = None
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyPolicyRotation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "type") and self.type is not None:
            _dict["type"] = self.type
        if hasattr(self, "rotation") and self.rotation is not None:
            if isinstance(self.rotation, dict):
                _dict["rotation"] = self.rotation
            else:
                _dict["rotation"] = self.rotation.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyPolicyRotation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyPolicyRotation") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyPolicyRotation") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        Specifies the MIME type that represents the policy resource. Currently, only the
        default is supported.
        """

        APPLICATION_VND_IBM_KMS_POLICY_JSON = "application/vnd.ibm.kms.policy+json"


class KeyPolicyRotationNonRequiredRotation:
    """
    Data associated with the automatic key rotation policy.

    :param bool enabled: If set to `true`, Key Protect enables a rotation policy on
          a single key.
    :param int interval_month: Specifies the key rotation time interval in
          approximate months standardized to 30 days each.  A minimum of 1 and a maximum
          of 12 can be set.
    """

    def __init__(
        self,
        enabled: bool,
        interval_month: int,
    ) -> None:
        """
        Initialize a KeyPolicyRotationNonRequiredRotation object.

        :param bool enabled: If set to `true`, Key Protect enables a rotation
               policy on a single key.
        :param int interval_month: Specifies the key rotation time interval in
               approximate months standardized to 30 days each.  A minimum of 1 and a
               maximum of 12 can be set.
        """
        self.enabled = enabled
        self.interval_month = interval_month

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyPolicyRotationNonRequiredRotation":
        """Initialize a KeyPolicyRotationNonRequiredRotation object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            raise ValueError(
                "Required property 'enabled' not present in KeyPolicyRotationNonRequiredRotation JSON"
            )
        if (interval_month := _dict.get("interval_month")) is not None:
            args["interval_month"] = interval_month
        else:
            raise ValueError(
                "Required property 'interval_month' not present in KeyPolicyRotationNonRequiredRotation JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyPolicyRotationNonRequiredRotation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        if hasattr(self, "interval_month") and self.interval_month is not None:
            _dict["interval_month"] = self.interval_month
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyPolicyRotationNonRequiredRotation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyPolicyRotationNonRequiredRotation") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyPolicyRotationNonRequiredRotation") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KeyPolicyRotationRotation:
    """
    Data associated with the automatic key rotation policy.

    :param bool enabled: If set to `true`, Key Protect enables a rotation policy on
          a single key.
    :param int interval_month: (optional) Specifies the key rotation time interval
          in approximate months standardized to 30 days each. A minimum of 1 and a maximum
          of 12 can be set.
    """

    def __init__(
        self,
        enabled: bool,
        *,
        interval_month: Optional[int] = None,
    ) -> None:
        """
        Initialize a KeyPolicyRotationRotation object.

        :param bool enabled: If set to `true`, Key Protect enables a rotation
               policy on a single key.
        :param int interval_month: (optional) Specifies the key rotation time
               interval in approximate months standardized to 30 days each. A minimum of 1
               and a maximum of 12 can be set.
        """
        self.enabled = enabled
        self.interval_month = interval_month

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyPolicyRotationRotation":
        """Initialize a KeyPolicyRotationRotation object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            args["enabled"] = None
        if (interval_month := _dict.get("interval_month")) is not None:
            args["interval_month"] = interval_month
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyPolicyRotationRotation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        if hasattr(self, "interval_month") and self.interval_month is not None:
            _dict["interval_month"] = self.interval_month
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyPolicyRotationRotation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyPolicyRotationRotation") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyPolicyRotationRotation") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KeyRing:
    """
    Base properties of an instance key ring.

    :param str id: (optional) An ID that identifies the key ring. Each ID is unique
          only within the given instance and is not reserved across the Key Protect
          service.
    :param datetime creation_date: (optional) The date the key ring was created. The
          date format follows RFC 3339.
    :param str created_by: (optional) The unique identifier for the user that
          created the key ring.
    """

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        creation_date: Optional[datetime] = None,
        created_by: Optional[str] = None,
    ) -> None:
        """
        Initialize a KeyRing object.

        :param str id: (optional) An ID that identifies the key ring. Each ID is
               unique only within the given instance and is not reserved across the Key
               Protect service.
        :param datetime creation_date: (optional) The date the key ring was
               created. The date format follows RFC 3339.
        :param str created_by: (optional) The unique identifier for the user that
               created the key ring.
        """
        self.id = id
        self.creation_date = creation_date
        self.created_by = created_by

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyRing":
        """Initialize a KeyRing object from a json dictionary."""
        args = {}
        if (id := _dict.get("id")) is not None:
            args["id"] = id
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (created_by := _dict.get("createdBy")) is not None:
            args["created_by"] = created_by
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyRing object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "id") and self.id is not None:
            _dict["id"] = self.id
        if hasattr(self, "creation_date") and self.creation_date is not None:
            _dict["creationDate"] = datetime_to_string(self.creation_date)
        if hasattr(self, "created_by") and self.created_by is not None:
            _dict["createdBy"] = self.created_by
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyRing object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyRing") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyRing") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KeyVersion:
    """
    Properties associated with a specific key version.

    :param str id: (optional) The ID of the key version.
    :param datetime creation_date: (optional) The date that the version of the key
          was created.
    """

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        creation_date: Optional[datetime] = None,
    ) -> None:
        """
        Initialize a KeyVersion object.

        """
        self.id = id
        self.creation_date = creation_date

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyVersion":
        """Initialize a KeyVersion object from a json dictionary."""
        args = {}
        if (id := _dict.get("id")) is not None:
            args["id"] = id
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyVersion object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "id") and getattr(self, "id") is not None:
            _dict["id"] = getattr(self, "id")
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyVersion object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyVersion") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyVersion") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KeyWithPayload:
    """
    Properties returned only for DELETE.

    :param str type: (optional) Specifies the MIME type that represents the key
          resource. Currently, only the default is supported.
    :param str id: (optional) The v4 UUID used to uniquely identify the resource, as
          specified by RFC 4122.
    :param str name: (optional) A human-readable name assigned to your key for
          convenience. To protect your privacy do not use personal data, such as your name
          or location, as the name for your key.
    :param List[str] aliases: (optional) One or more, up to a total of five,
          human-readable unique aliases assigned to your key. To protect your privacy do
          not use personal data, such as your name or location, as an alias for your key.
          Each alias must be alphanumeric and cannot contain spaces or special characters
          other than `-` or `_`. The alias cannot be a UUID and must not be a Key Protect
          reserved name: `allowed_ip`, `key`, `keys`, `metadata`, `policy`, `policies`,
          `registration`, `registrations`, `ring`, `rings`, `rotate`, `wrap`, `unwrap`,
          `rewrap`, `version`, `versions`.
    :param str description: (optional) A text field used to provide a more detailed
          description of the key. The maximum length is 240 characters. To protect your
          privacy, do not use personal data, such as your name or location, as a
          description for your key.
    :param List[str] tags: (optional) Up to 30 tags can be created. Tags can be
          between 0-30 characters, including spaces. Special characters not permitted
          include angled brackets, comma, colon, ampersand, and vertical pipe character
          (|). To protect your privacy, do not use personal data, such as your name or
          location, as a tag for your key.
    :param int state: (optional) The key state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :param datetime expiration_date: (optional) The date and time that the key
          expires in the system, in RFC 3339 format (YYYY-MM-DD HH:MM:SS.SS, for example
          2019-10-12T07:20:50.52Z). Keys created with an expiration date automatically
          transition to the Deactivated state within one hour after expiration. In this
          state, the only allowed actions on the key are unwrap, rewrap, rotate, and
          delete. Deactivated keys cannot be used to encrypt (wrap) new data, even if
          rotated while deactivated. Rotation does not reset or extend the expiration
          date, nor does it allow the date to be changed. It is recommended that any data
          encrypted with an expiring or expired key be re-encrypted using a new customer
          root key (CRK) before the original CRK expires, to prevent service disruptions.
          Deleting and restoring a deactivated key does not move it back to the Active
          state. If the expirationDate attribute is omitted, the key does not expire.
    :param bool extractable: (optional) A boolean that determines whether the key
          material can leave the service. If set to `false`, Key Protect designates the
          key as a nonextractable root key used for `wrap` and `unwrap` actions. If set to
          `true`, Key Protect designates the key as a standard key that you can store in
          your apps and services. Once set to `false` it cannot be changed to `true`.
    :param str crn: (optional) The Cloud Resource Name (CRN) that uniquely
          identifies your cloud resources.
    :param bool imported: (optional) A boolean that shows whether your key was
          originally imported or generated in Key Protect. The value is set by Key Protect
          based on how the key material is initially added to the service. A value of
          `true` indicates that you must provide new key material when it's time to rotate
          the key. A value of `false` indicates that Key Protect will generate the new key
          material on a `rotate` operation, as it did in key creation.
    :param str key_ring_id: (optional) An ID that identifies the key ring. Each ID
          is unique only within the given instance and is not reserved across the Key
          Protect service.
    :param datetime creation_date: (optional) The date the key material was created.
          The date format follows RFC 3339.
    :param str created_by: (optional) The unique identifier for the resource that
          created the key.
    :param str algorithm_type: (optional) Deprecated: Deprecated.
    :param KeyWithPayloadAlgorithmMetadata algorithm_metadata: (optional)
          Deprecated.
    :param int algorithm_bit_size: (optional) Deprecated: Deprecated.
    :param str algorithm_mode: (optional) Deprecated: Deprecated.
    :param int nonactive_state_reason: (optional) A code indicating the reason the
          key is not in the activation state.
    :param datetime last_update_date: (optional) Updates when any part of the key
          metadata is modified. The date format follows RFC 3339.
    :param datetime last_rotate_date: (optional) Updates to show when the key was
          last rotated. The date format follows RFC 3339.
    :param KeyVersion key_version: (optional) Properties associated with a specific
          key version.
    :param DualAuthKeyMetadata dual_auth_delete: (optional) Metadata that indicates
          the status of a dual authorization policy on the key.
    :param RotationKeyMetadata rotation: (optional) Metadata that indicates the
          status of a rotation policy on the key.
    :param bool deleted: (optional) A boolean that determines whether the key has
          been deleted.
    :param datetime deletion_date: (optional) The date the key material was
          destroyed. The date format follows RFC 3339.
    :param str deleted_by: (optional) The unique identifier for the resource that
          deleted the key.
    :param datetime restore_expiration_date: (optional) The date the key will no
          longer have the ability to be restored.
    :param bool restore_allowed: (optional) A boolean that specifies if your key has
          the ability to be restored. A value of `true` indicates that the key can be
          restored. A value of `false` indicates that the key is unable to be restored.
    :param bool purge_allowed: (optional) A boolean that specifies if the key can be
          purged. A value of `true` indicates that the key can be purged. A value of
          `false` indicates that the key is within the purge wait period and is not ready
          to be purged.
    :param datetime purge_allowed_from: (optional) The date the key will be ready to
          be purged.
    :param datetime purge_scheduled_on: (optional) The date the deleted key will be
          automatically purged from Key Protect system.
    :param bytes payload: (optional) The key material that you can export to
          external apps or services.
          **Note:** If the key has been designated as a root key, the system cannot return
          the key material.
    """

    def __init__(
        self,
        *,
        type: Optional[str] = None,
        id: Optional[str] = None,
        name: Optional[str] = None,
        aliases: Optional[List[str]] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
        state: Optional[int] = None,
        expiration_date: Optional[datetime] = None,
        extractable: Optional[bool] = None,
        crn: Optional[str] = None,
        imported: Optional[bool] = None,
        key_ring_id: Optional[str] = None,
        creation_date: Optional[datetime] = None,
        created_by: Optional[str] = None,
        algorithm_type: Optional[str] = None,
        algorithm_metadata: Optional["KeyWithPayloadAlgorithmMetadata"] = None,
        algorithm_bit_size: Optional[int] = None,
        algorithm_mode: Optional[str] = None,
        nonactive_state_reason: Optional[int] = None,
        last_update_date: Optional[datetime] = None,
        last_rotate_date: Optional[datetime] = None,
        key_version: Optional["KeyVersion"] = None,
        dual_auth_delete: Optional["DualAuthKeyMetadata"] = None,
        rotation: Optional["RotationKeyMetadata"] = None,
        deleted: Optional[bool] = None,
        deletion_date: Optional[datetime] = None,
        deleted_by: Optional[str] = None,
        restore_expiration_date: Optional[datetime] = None,
        restore_allowed: Optional[bool] = None,
        purge_allowed: Optional[bool] = None,
        purge_allowed_from: Optional[datetime] = None,
        purge_scheduled_on: Optional[datetime] = None,
        payload: Optional[bytes] = None,
    ) -> None:
        """
        Initialize a KeyWithPayload object.

        :param str type: (optional) Specifies the MIME type that represents the key
               resource. Currently, only the default is supported.
        :param str name: (optional) A human-readable name assigned to your key for
               convenience. To protect your privacy do not use personal data, such as your
               name or location, as the name for your key.
        :param List[str] aliases: (optional) One or more, up to a total of five,
               human-readable unique aliases assigned to your key. To protect your privacy
               do not use personal data, such as your name or location, as an alias for
               your key. Each alias must be alphanumeric and cannot contain spaces or
               special characters other than `-` or `_`. The alias cannot be a UUID and
               must not be a Key Protect reserved name: `allowed_ip`, `key`, `keys`,
               `metadata`, `policy`, `policies`, `registration`, `registrations`, `ring`,
               `rings`, `rotate`, `wrap`, `unwrap`, `rewrap`, `version`, `versions`.
        :param str description: (optional) A text field used to provide a more
               detailed description of the key. The maximum length is 240 characters. To
               protect your privacy, do not use personal data, such as your name or
               location, as a description for your key.
        :param List[str] tags: (optional) Up to 30 tags can be created. Tags can be
               between 0-30 characters, including spaces. Special characters not permitted
               include angled brackets, comma, colon, ampersand, and vertical pipe
               character (|). To protect your privacy, do not use personal data, such as
               your name or location, as a tag for your key.
        :param bool extractable: (optional) A boolean that determines whether the
               key material can leave the service. If set to `false`, Key Protect
               designates the key as a nonextractable root key used for `wrap` and
               `unwrap` actions. If set to `true`, Key Protect designates the key as a
               standard key that you can store in your apps and services. Once set to
               `false` it cannot be changed to `true`.
        :param str key_ring_id: (optional) An ID that identifies the key ring. Each
               ID is unique only within the given instance and is not reserved across the
               Key Protect service.
        :param int algorithm_bit_size: (optional) Deprecated: Deprecated.
        :param str algorithm_mode: (optional) Deprecated: Deprecated.
        :param DualAuthKeyMetadata dual_auth_delete: (optional) Metadata that
               indicates the status of a dual authorization policy on the key.
        :param RotationKeyMetadata rotation: (optional) Metadata that indicates the
               status of a rotation policy on the key.
        :param datetime restore_expiration_date: (optional) The date the key will
               no longer have the ability to be restored.
        :param bool restore_allowed: (optional) A boolean that specifies if your
               key has the ability to be restored. A value of `true` indicates that the
               key can be restored. A value of `false` indicates that the key is unable to
               be restored.
        :param bool purge_allowed: (optional) A boolean that specifies if the key
               can be purged. A value of `true` indicates that the key can be purged. A
               value of `false` indicates that the key is within the purge wait period and
               is not ready to be purged.
        :param datetime purge_allowed_from: (optional) The date the key will be
               ready to be purged.
        :param datetime purge_scheduled_on: (optional) The date the deleted key
               will be automatically purged from Key Protect system.
        """
        self.type = type
        self.id = id
        self.name = name
        self.aliases = aliases
        self.description = description
        self.tags = tags
        self.state = state
        self.expiration_date = expiration_date
        self.extractable = extractable
        self.crn = crn
        self.imported = imported
        self.key_ring_id = key_ring_id
        self.creation_date = creation_date
        self.created_by = created_by
        self.algorithm_type = algorithm_type
        self.algorithm_metadata = algorithm_metadata
        self.algorithm_bit_size = algorithm_bit_size
        self.algorithm_mode = algorithm_mode
        self.nonactive_state_reason = nonactive_state_reason
        self.last_update_date = last_update_date
        self.last_rotate_date = last_rotate_date
        self.key_version = key_version
        self.dual_auth_delete = dual_auth_delete
        self.rotation = rotation
        self.deleted = deleted
        self.deletion_date = deletion_date
        self.deleted_by = deleted_by
        self.restore_expiration_date = restore_expiration_date
        self.restore_allowed = restore_allowed
        self.purge_allowed = purge_allowed
        self.purge_allowed_from = purge_allowed_from
        self.purge_scheduled_on = purge_scheduled_on
        self.payload = payload

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyWithPayload":
        """Initialize a KeyWithPayload object from a json dictionary."""
        args = {}
        if (type := _dict.get("type")) is not None:
            args["type"] = type
        if (id := _dict.get("id")) is not None:
            args["id"] = id
        if (name := _dict.get("name")) is not None:
            args["name"] = name
        if (aliases := _dict.get("aliases")) is not None:
            args["aliases"] = aliases
        if (description := _dict.get("description")) is not None:
            args["description"] = description
        if (tags := _dict.get("tags")) is not None:
            args["tags"] = tags
        if (state := _dict.get("state")) is not None:
            args["state"] = state
        if (expiration_date := _dict.get("expirationDate")) is not None:
            args["expiration_date"] = string_to_datetime(expiration_date)
        if (extractable := _dict.get("extractable")) is not None:
            args["extractable"] = extractable
        if (crn := _dict.get("crn")) is not None:
            args["crn"] = crn
        if (imported := _dict.get("imported")) is not None:
            args["imported"] = imported
        if (key_ring_id := _dict.get("keyRingID")) is not None:
            args["key_ring_id"] = key_ring_id
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (created_by := _dict.get("createdBy")) is not None:
            args["created_by"] = created_by
        if (algorithm_type := _dict.get("algorithmType")) is not None:
            args["algorithm_type"] = algorithm_type
        if (algorithm_metadata := _dict.get("algorithmMetadata")) is not None:
            args["algorithm_metadata"] = KeyWithPayloadAlgorithmMetadata.from_dict(
                algorithm_metadata
            )
        if (algorithm_bit_size := _dict.get("algorithmBitSize")) is not None:
            args["algorithm_bit_size"] = algorithm_bit_size
        if (algorithm_mode := _dict.get("algorithmMode")) is not None:
            args["algorithm_mode"] = algorithm_mode
        if (nonactive_state_reason := _dict.get("nonactiveStateReason")) is not None:
            args["nonactive_state_reason"] = nonactive_state_reason
        if (last_update_date := _dict.get("lastUpdateDate")) is not None:
            args["last_update_date"] = string_to_datetime(last_update_date)
        if (last_rotate_date := _dict.get("lastRotateDate")) is not None:
            args["last_rotate_date"] = string_to_datetime(last_rotate_date)
        if (key_version := _dict.get("keyVersion")) is not None:
            args["key_version"] = KeyVersion.from_dict(key_version)
        if (dual_auth_delete := _dict.get("dualAuthDelete")) is not None:
            args["dual_auth_delete"] = DualAuthKeyMetadata.from_dict(dual_auth_delete)
        if (rotation := _dict.get("rotation")) is not None:
            args["rotation"] = RotationKeyMetadata.from_dict(rotation)
        if (deleted := _dict.get("deleted")) is not None:
            args["deleted"] = deleted
        if (deletion_date := _dict.get("deletionDate")) is not None:
            args["deletion_date"] = string_to_datetime(deletion_date)
        if (deleted_by := _dict.get("deletedBy")) is not None:
            args["deleted_by"] = deleted_by
        if (restore_expiration_date := _dict.get("restoreExpirationDate")) is not None:
            args["restore_expiration_date"] = string_to_datetime(
                restore_expiration_date
            )
        if (restore_allowed := _dict.get("restoreAllowed")) is not None:
            args["restore_allowed"] = restore_allowed
        if (purge_allowed := _dict.get("purgeAllowed")) is not None:
            args["purge_allowed"] = purge_allowed
        if (purge_allowed_from := _dict.get("purgeAllowedFrom")) is not None:
            args["purge_allowed_from"] = string_to_datetime(purge_allowed_from)
        if (purge_scheduled_on := _dict.get("purgeScheduledOn")) is not None:
            args["purge_scheduled_on"] = string_to_datetime(purge_scheduled_on)
        if (payload := _dict.get("payload")) is not None:
            args["payload"] = base64.b64decode(payload)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyWithPayload object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "type") and self.type is not None:
            _dict["type"] = self.type
        if hasattr(self, "id") and getattr(self, "id") is not None:
            _dict["id"] = getattr(self, "id")
        if hasattr(self, "name") and self.name is not None:
            _dict["name"] = self.name
        if hasattr(self, "aliases") and self.aliases is not None:
            _dict["aliases"] = self.aliases
        if hasattr(self, "description") and self.description is not None:
            _dict["description"] = self.description
        if hasattr(self, "tags") and self.tags is not None:
            _dict["tags"] = self.tags
        if hasattr(self, "state") and getattr(self, "state") is not None:
            _dict["state"] = getattr(self, "state")
        if (
            hasattr(self, "expiration_date")
            and getattr(self, "expiration_date") is not None
        ):
            _dict["expirationDate"] = datetime_to_string(
                getattr(self, "expiration_date")
            )
        if hasattr(self, "extractable") and self.extractable is not None:
            _dict["extractable"] = self.extractable
        if hasattr(self, "crn") and getattr(self, "crn") is not None:
            _dict["crn"] = getattr(self, "crn")
        if hasattr(self, "imported") and getattr(self, "imported") is not None:
            _dict["imported"] = getattr(self, "imported")
        if hasattr(self, "key_ring_id") and self.key_ring_id is not None:
            _dict["keyRingID"] = self.key_ring_id
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        if hasattr(self, "created_by") and getattr(self, "created_by") is not None:
            _dict["createdBy"] = getattr(self, "created_by")
        if (
            hasattr(self, "algorithm_type")
            and getattr(self, "algorithm_type") is not None
        ):
            _dict["algorithmType"] = getattr(self, "algorithm_type")
        if (
            hasattr(self, "algorithm_metadata")
            and getattr(self, "algorithm_metadata") is not None
        ):
            if isinstance(getattr(self, "algorithm_metadata"), dict):
                _dict["algorithmMetadata"] = getattr(self, "algorithm_metadata")
            else:
                _dict["algorithmMetadata"] = getattr(
                    self, "algorithm_metadata"
                ).to_dict()
        if hasattr(self, "algorithm_bit_size") and self.algorithm_bit_size is not None:
            _dict["algorithmBitSize"] = self.algorithm_bit_size
        if hasattr(self, "algorithm_mode") and self.algorithm_mode is not None:
            _dict["algorithmMode"] = self.algorithm_mode
        if (
            hasattr(self, "nonactive_state_reason")
            and getattr(self, "nonactive_state_reason") is not None
        ):
            _dict["nonactiveStateReason"] = getattr(self, "nonactive_state_reason")
        if (
            hasattr(self, "last_update_date")
            and getattr(self, "last_update_date") is not None
        ):
            _dict["lastUpdateDate"] = datetime_to_string(
                getattr(self, "last_update_date")
            )
        if (
            hasattr(self, "last_rotate_date")
            and getattr(self, "last_rotate_date") is not None
        ):
            _dict["lastRotateDate"] = datetime_to_string(
                getattr(self, "last_rotate_date")
            )
        if hasattr(self, "key_version") and getattr(self, "key_version") is not None:
            if isinstance(getattr(self, "key_version"), dict):
                _dict["keyVersion"] = getattr(self, "key_version")
            else:
                _dict["keyVersion"] = getattr(self, "key_version").to_dict()
        if hasattr(self, "dual_auth_delete") and self.dual_auth_delete is not None:
            if isinstance(self.dual_auth_delete, dict):
                _dict["dualAuthDelete"] = self.dual_auth_delete
            else:
                _dict["dualAuthDelete"] = self.dual_auth_delete.to_dict()
        if hasattr(self, "rotation") and self.rotation is not None:
            if isinstance(self.rotation, dict):
                _dict["rotation"] = self.rotation
            else:
                _dict["rotation"] = self.rotation.to_dict()
        if hasattr(self, "deleted") and getattr(self, "deleted") is not None:
            _dict["deleted"] = getattr(self, "deleted")
        if (
            hasattr(self, "deletion_date")
            and getattr(self, "deletion_date") is not None
        ):
            _dict["deletionDate"] = datetime_to_string(getattr(self, "deletion_date"))
        if hasattr(self, "deleted_by") and getattr(self, "deleted_by") is not None:
            _dict["deletedBy"] = getattr(self, "deleted_by")
        if (
            hasattr(self, "restore_expiration_date")
            and self.restore_expiration_date is not None
        ):
            _dict["restoreExpirationDate"] = datetime_to_string(
                self.restore_expiration_date
            )
        if hasattr(self, "restore_allowed") and self.restore_allowed is not None:
            _dict["restoreAllowed"] = self.restore_allowed
        if hasattr(self, "purge_allowed") and self.purge_allowed is not None:
            _dict["purgeAllowed"] = self.purge_allowed
        if hasattr(self, "purge_allowed_from") and self.purge_allowed_from is not None:
            _dict["purgeAllowedFrom"] = datetime_to_string(self.purge_allowed_from)
        if hasattr(self, "purge_scheduled_on") and self.purge_scheduled_on is not None:
            _dict["purgeScheduledOn"] = datetime_to_string(self.purge_scheduled_on)
        if hasattr(self, "payload") and getattr(self, "payload") is not None:
            _dict["payload"] = str(base64.b64encode(getattr(self, "payload")), "utf-8")
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyWithPayload object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyWithPayload") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyWithPayload") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        Specifies the MIME type that represents the key resource. Currently, only the
        default is supported.
        """

        APPLICATION_VND_IBM_KMS_KEY_JSON = "application/vnd.ibm.kms.key+json"

    class AlgorithmTypeEnum(str, Enum):
        """
        Deprecated.
        """

        AES = "AES"
        DEPRECATED = "Deprecated"

    class AlgorithmModeEnum(str, Enum):
        """
        Deprecated.
        """

        CBC_PAD = "CBC_PAD"
        DEPRECATED = "Deprecated"


class KeyWithPayloadAlgorithmMetadata:
    """
    Deprecated.

    :param str bit_length: (optional) Deprecated.
    :param str mode: (optional) Deprecated.
    """

    def __init__(
        self,
        *,
        bit_length: Optional[str] = None,
        mode: Optional[str] = None,
    ) -> None:
        """
        Initialize a KeyWithPayloadAlgorithmMetadata object.

        :param str bit_length: (optional) Deprecated.
        :param str mode: (optional) Deprecated.
        """
        self.bit_length = bit_length
        self.mode = mode

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyWithPayloadAlgorithmMetadata":
        """Initialize a KeyWithPayloadAlgorithmMetadata object from a json dictionary."""
        args = {}
        if (bit_length := _dict.get("bitLength")) is not None:
            args["bit_length"] = bit_length
        if (mode := _dict.get("mode")) is not None:
            args["mode"] = mode
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyWithPayloadAlgorithmMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "bit_length") and self.bit_length is not None:
            _dict["bitLength"] = self.bit_length
        if hasattr(self, "mode") and self.mode is not None:
            _dict["mode"] = self.mode
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyWithPayloadAlgorithmMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyWithPayloadAlgorithmMetadata") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyWithPayloadAlgorithmMetadata") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class ModeEnum(str, Enum):
        """
        Deprecated.
        """

        CBC_PAD = "CBC_PAD"
        DEPRECATED = "Deprecated"


class ListCollectionMetadata:
    """
    ListCollectionMetadata.

    """

    def __init__(
        self,
    ) -> None:
        """
        Initialize a ListCollectionMetadata object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(
                [
                    "ListCollectionMetadataCollectionMetadataWithTotalCount",
                    "ListCollectionMetadataCollectionMetadata",
                ]
            )
        )
        raise Exception(msg)


class ListKMIPAdapters:
    """
    The base schema for listing kmip adapter(s).

    :param ListCollectionMetadata metadata: (optional)
    :param List[KMIPAdapter] resources: (optional) A collection of resources.
    """

    def __init__(
        self,
        *,
        metadata: Optional["ListCollectionMetadata"] = None,
        resources: Optional[List["KMIPAdapter"]] = None,
    ) -> None:
        """
        Initialize a ListKMIPAdapters object.

        :param ListCollectionMetadata metadata: (optional)
        :param List[KMIPAdapter] resources: (optional) A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "ListKMIPAdapters":
        """Initialize a ListKMIPAdapters object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = metadata
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [KMIPAdapter.from_dict(v) for v in resources]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListKMIPAdapters object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListKMIPAdapters object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "ListKMIPAdapters") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "ListKMIPAdapters") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListKMIPAdaptersWithTotalCount:
    """
    The base schema for listing kmip adapter with total count.

    :param CollectionMetadataWithTotalCount metadata: The metadata that describes
          the resource array.
    :param List[KMIPAdapter] resources: (optional) A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadataWithTotalCount",
        *,
        resources: Optional[List["KMIPAdapter"]] = None,
    ) -> None:
        """
        Initialize a ListKMIPAdaptersWithTotalCount object.

        :param CollectionMetadataWithTotalCount metadata: The metadata that
               describes the resource array.
        :param List[KMIPAdapter] resources: (optional) A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "ListKMIPAdaptersWithTotalCount":
        """Initialize a ListKMIPAdaptersWithTotalCount object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadataWithTotalCount.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in ListKMIPAdaptersWithTotalCount JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [KMIPAdapter.from_dict(v) for v in resources]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListKMIPAdaptersWithTotalCount object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListKMIPAdaptersWithTotalCount object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "ListKMIPAdaptersWithTotalCount") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "ListKMIPAdaptersWithTotalCount") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListKMIPClientCertificates:
    """
    The base schema for listing client certificates in a kmip adapter.

    :param ListCollectionMetadata metadata: (optional)
    :param List[KMIPClientCertificate] resources: (optional) A collection of
          resources.
    """

    def __init__(
        self,
        *,
        metadata: Optional["ListCollectionMetadata"] = None,
        resources: Optional[List["KMIPClientCertificate"]] = None,
    ) -> None:
        """
        Initialize a ListKMIPClientCertificates object.

        :param ListCollectionMetadata metadata: (optional)
        :param List[KMIPClientCertificate] resources: (optional) A collection of
               resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "ListKMIPClientCertificates":
        """Initialize a ListKMIPClientCertificates object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = metadata
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [KMIPClientCertificate.from_dict(v) for v in resources]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListKMIPClientCertificates object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListKMIPClientCertificates object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "ListKMIPClientCertificates") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "ListKMIPClientCertificates") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListKMIPObjectsWithTotalCount:
    """
    The base schema for listing kmip objects in a kmip adapter with total count.

    :param CollectionMetadataWithTotalCount metadata: The metadata that describes
          the resource array.
    :param List[KMIPObject] resources: (optional) A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadataWithTotalCount",
        *,
        resources: Optional[List["KMIPObject"]] = None,
    ) -> None:
        """
        Initialize a ListKMIPObjectsWithTotalCount object.

        :param CollectionMetadataWithTotalCount metadata: The metadata that
               describes the resource array.
        :param List[KMIPObject] resources: (optional) A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "ListKMIPObjectsWithTotalCount":
        """Initialize a ListKMIPObjectsWithTotalCount object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadataWithTotalCount.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in ListKMIPObjectsWithTotalCount JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [KMIPObject.from_dict(v) for v in resources]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListKMIPObjectsWithTotalCount object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListKMIPObjectsWithTotalCount object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "ListKMIPObjectsWithTotalCount") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "ListKMIPObjectsWithTotalCount") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListKMIPPartialClientCertificatesWithTotalCount:
    """
    The base schema for listing client certificates in a kmip adapter with total count.

    :param CollectionMetadataWithTotalCount metadata: The metadata that describes
          the resource array.
    :param List[KMIPClientPartialCertificate] resources: (optional) A collection of
          resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadataWithTotalCount",
        *,
        resources: Optional[List["KMIPClientPartialCertificate"]] = None,
    ) -> None:
        """
        Initialize a ListKMIPPartialClientCertificatesWithTotalCount object.

        :param CollectionMetadataWithTotalCount metadata: The metadata that
               describes the resource array.
        :param List[KMIPClientPartialCertificate] resources: (optional) A
               collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "ListKMIPPartialClientCertificatesWithTotalCount":
        """Initialize a ListKMIPPartialClientCertificatesWithTotalCount object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadataWithTotalCount.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in ListKMIPPartialClientCertificatesWithTotalCount JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                KMIPClientPartialCertificate.from_dict(v) for v in resources
            ]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListKMIPPartialClientCertificatesWithTotalCount object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListKMIPPartialClientCertificatesWithTotalCount object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "ListKMIPPartialClientCertificatesWithTotalCount") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "ListKMIPPartialClientCertificatesWithTotalCount") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListKeyRingsWithTotalCount:
    """
    The base schema for listing key rings.

    :param CollectionMetadataWithTotalCount metadata: The metadata that describes
          the resource array.
    :param List[KeyRing] resources: (optional) A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadataWithTotalCount",
        *,
        resources: Optional[List["KeyRing"]] = None,
    ) -> None:
        """
        Initialize a ListKeyRingsWithTotalCount object.

        :param CollectionMetadataWithTotalCount metadata: The metadata that
               describes the resource array.
        :param List[KeyRing] resources: (optional) A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "ListKeyRingsWithTotalCount":
        """Initialize a ListKeyRingsWithTotalCount object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadataWithTotalCount.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in ListKeyRingsWithTotalCount JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [KeyRing.from_dict(v) for v in resources]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListKeyRingsWithTotalCount object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListKeyRingsWithTotalCount object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "ListKeyRingsWithTotalCount") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "ListKeyRingsWithTotalCount") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListKeyVersions:
    """
    Properties associated with a registration response.

    :param ListCollectionMetadata metadata: (optional)
    :param List[KeyVersion] resources: (optional) An array of resources.
    """

    def __init__(
        self,
        *,
        metadata: Optional["ListCollectionMetadata"] = None,
        resources: Optional[List["KeyVersion"]] = None,
    ) -> None:
        """
        Initialize a ListKeyVersions object.

        :param ListCollectionMetadata metadata: (optional)
        :param List[KeyVersion] resources: (optional) An array of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "ListKeyVersions":
        """Initialize a ListKeyVersions object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = metadata
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [KeyVersion.from_dict(v) for v in resources]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListKeyVersions object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListKeyVersions object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "ListKeyVersions") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "ListKeyVersions") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListKeys:
    """
    The base schema for listing keys.

    :param CollectionMetadataListKeys metadata: The metadata that describes the list
          keys response.
    :param List[KeyFullRepresentation] resources: (optional) A collection of
          resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadataListKeys",
        *,
        resources: Optional[List["KeyFullRepresentation"]] = None,
    ) -> None:
        """
        Initialize a ListKeys object.

        :param CollectionMetadataListKeys metadata: The metadata that describes the
               list keys response.
        :param List[KeyFullRepresentation] resources: (optional) A collection of
               resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "ListKeys":
        """Initialize a ListKeys object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadataListKeys.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in ListKeys JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [KeyFullRepresentation.from_dict(v) for v in resources]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListKeys object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListKeys object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "ListKeys") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "ListKeys") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListKeysMetadataPropertiesSearchQuery:
    """
    Represents the parsed search query used for matching logic. Only returned when a
    search is requested.

    :param str query: final string to use for matching logic.
    :param List[str] scopes: list of scopes to search in.
    :param bool not_: (optional) invert matching logic.
    :param bool exact: (optional) only match query strings that are fully identical
          (case insensitive).
    """

    def __init__(
        self,
        query: str,
        scopes: List[str],
        *,
        not_: Optional[bool] = None,
        exact: Optional[bool] = None,
    ) -> None:
        """
        Initialize a ListKeysMetadataPropertiesSearchQuery object.

        :param str query: final string to use for matching logic.
        :param List[str] scopes: list of scopes to search in.
        :param bool not_: (optional) invert matching logic.
        :param bool exact: (optional) only match query strings that are fully
               identical (case insensitive).
        """
        self.query = query
        self.scopes = scopes
        self.not_ = not_
        self.exact = exact

    @classmethod
    def from_dict(cls, _dict: Dict) -> "ListKeysMetadataPropertiesSearchQuery":
        """Initialize a ListKeysMetadataPropertiesSearchQuery object from a json dictionary."""
        args = {}
        if (query := _dict.get("query")) is not None:
            args["query"] = query
        else:
            raise ValueError(
                "Required property 'query' not present in ListKeysMetadataPropertiesSearchQuery JSON"
            )
        if (scopes := _dict.get("scopes")) is not None:
            args["scopes"] = scopes
        else:
            raise ValueError(
                "Required property 'scopes' not present in ListKeysMetadataPropertiesSearchQuery JSON"
            )
        if (not_ := _dict.get("not")) is not None:
            args["not_"] = not_
        if (exact := _dict.get("exact")) is not None:
            args["exact"] = exact
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListKeysMetadataPropertiesSearchQuery object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "query") and self.query is not None:
            _dict["query"] = self.query
        if hasattr(self, "scopes") and self.scopes is not None:
            _dict["scopes"] = self.scopes
        if hasattr(self, "not_") and self.not_ is not None:
            _dict["not"] = self.not_
        if hasattr(self, "exact") and self.exact is not None:
            _dict["exact"] = self.exact
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListKeysMetadataPropertiesSearchQuery object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "ListKeysMetadataPropertiesSearchQuery") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "ListKeysMetadataPropertiesSearchQuery") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class ScopesEnum(str, Enum):
        """
        scopes.
        """

        NAME = "name"
        ALIAS = "alias"


class MetricsProperties:
    """
    User defined metadata that is associated with the `metrics` instance policy type.

    :param bool enabled: If set to `true`, Key Protect will send service instance
          metrics to your [Cloud Monitoring With
          Sysdig](/docs/Monitoring-with-Sysdig?topic=Monitoring-with-Sysdig-getting-started)
          monitoring instance. By default, sending metrics to your [Cloud Monitoring With
          Sysdig](/docs/Monitoring-with-Sysdig?topic=Monitoring-with-Sysdig-getting-started)
          monitoring instance is disabled.
          **Note:** A metrics policy will add an additional metrics source to your [Cloud
          Monitoring With
          Sysdig](/docs/Monitoring-with-Sysdig?topic=Monitoring-with-Sysdig-getting-started)
          monitoring instance. For more information, see [Enabling Platform
          Metrics](/docs/Monitoring-with-Sysdig?topic=Monitoring-with-Sysdig-platform_metrics_enabling)
          for more information.
    """

    def __init__(
        self,
        enabled: bool,
    ) -> None:
        """
        Initialize a MetricsProperties object.

        :param bool enabled: If set to `true`, Key Protect will send service
               instance metrics to your [Cloud Monitoring With
               Sysdig](/docs/Monitoring-with-Sysdig?topic=Monitoring-with-Sysdig-getting-started)
               monitoring instance. By default, sending metrics to your [Cloud Monitoring
               With
               Sysdig](/docs/Monitoring-with-Sysdig?topic=Monitoring-with-Sysdig-getting-started)
               monitoring instance is disabled.
               **Note:** A metrics policy will add an additional metrics source to your
               [Cloud Monitoring With
               Sysdig](/docs/Monitoring-with-Sysdig?topic=Monitoring-with-Sysdig-getting-started)
               monitoring instance. For more information, see [Enabling Platform
               Metrics](/docs/Monitoring-with-Sysdig?topic=Monitoring-with-Sysdig-platform_metrics_enabling)
               for more information.
        """
        self.enabled = enabled

    @classmethod
    def from_dict(cls, _dict: Dict) -> "MetricsProperties":
        """Initialize a MetricsProperties object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            raise ValueError(
                "Required property 'enabled' not present in MetricsProperties JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a MetricsProperties object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this MetricsProperties object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "MetricsProperties") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "MetricsProperties") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PatchKeyResponseBody:
    """
    The base schema for patch key response body.

    :param CollectionMetadata metadata: (optional) The metadata that describes the
          resource array.
    :param List[KeyFullRepresentation] resources: (optional) An array of resources.
    """

    def __init__(
        self,
        *,
        metadata: Optional["CollectionMetadata"] = None,
        resources: Optional[List["KeyFullRepresentation"]] = None,
    ) -> None:
        """
        Initialize a PatchKeyResponseBody object.

        :param CollectionMetadata metadata: (optional) The metadata that describes
               the resource array.
        :param List[KeyFullRepresentation] resources: (optional) An array of
               resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "PatchKeyResponseBody":
        """Initialize a PatchKeyResponseBody object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [KeyFullRepresentation.from_dict(v) for v in resources]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PatchKeyResponseBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PatchKeyResponseBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "PatchKeyResponseBody") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "PatchKeyResponseBody") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PurgeKey:
    """
    The base schema for purged key.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param List[KeyFullRepresentation] resources: A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List["KeyFullRepresentation"],
    ) -> None:
        """
        Initialize a PurgeKey object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[KeyFullRepresentation] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "PurgeKey":
        """Initialize a PurgeKey object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in PurgeKey JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [KeyFullRepresentation.from_dict(v) for v in resources]
        else:
            raise ValueError(
                "Required property 'resources' not present in PurgeKey JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PurgeKey object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PurgeKey object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "PurgeKey") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "PurgeKey") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RegistrationResource:
    """
    Properties associated with a registration.

    :param str key_id: (optional) The ID that identifies the root key that is
          associated with the specified cloud resource.
    :param str key_name: (optional) The human-readable reference assigned to the key
          that is associated with the specified cloud resource.
    :param str resource_crn: (optional) The [Cloud Resource
          Name](/docs/account?topic=account-crn) (CRN) that represents the cloud resource,
          such as a Cloud Object Storage bucket, that is associated with the key.
    :param str created_by: (optional) The unique identifier for the resource that
          created the registration.
    :param datetime creation_date: (optional) The date the registration was created.
          The date format follows RFC 3339.
    :param str updated_by: (optional) The unique identifier for the resource that
          updated the registration.
    :param datetime last_updated: (optional) Updates when the registration is
          modified. The date format follows RFC 3339.
    :param str description: (optional) Description of the purpose of the
          registration.
    :param bool prevent_key_deletion: (optional) A boolean that determines whether
          Key Protect must prevent deletion of a root key.
    :param KeyVersion key_version: (optional) Properties associated with a specific
          key version.
    """

    def __init__(
        self,
        *,
        key_id: Optional[str] = None,
        key_name: Optional[str] = None,
        resource_crn: Optional[str] = None,
        created_by: Optional[str] = None,
        creation_date: Optional[datetime] = None,
        updated_by: Optional[str] = None,
        last_updated: Optional[datetime] = None,
        description: Optional[str] = None,
        prevent_key_deletion: Optional[bool] = None,
        key_version: Optional["KeyVersion"] = None,
    ) -> None:
        """
        Initialize a RegistrationResource object.

        """
        self.key_id = key_id
        self.key_name = key_name
        self.resource_crn = resource_crn
        self.created_by = created_by
        self.creation_date = creation_date
        self.updated_by = updated_by
        self.last_updated = last_updated
        self.description = description
        self.prevent_key_deletion = prevent_key_deletion
        self.key_version = key_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> "RegistrationResource":
        """Initialize a RegistrationResource object from a json dictionary."""
        args = {}
        if (key_id := _dict.get("keyId")) is not None:
            args["key_id"] = key_id
        if (key_name := _dict.get("keyName")) is not None:
            args["key_name"] = key_name
        if (resource_crn := _dict.get("resourceCrn")) is not None:
            args["resource_crn"] = resource_crn
        if (created_by := _dict.get("createdBy")) is not None:
            args["created_by"] = created_by
        if (creation_date := _dict.get("creationDate")) is not None:
            args["creation_date"] = string_to_datetime(creation_date)
        if (updated_by := _dict.get("updatedBy")) is not None:
            args["updated_by"] = updated_by
        if (last_updated := _dict.get("lastUpdated")) is not None:
            args["last_updated"] = string_to_datetime(last_updated)
        if (description := _dict.get("description")) is not None:
            args["description"] = description
        if (prevent_key_deletion := _dict.get("preventKeyDeletion")) is not None:
            args["prevent_key_deletion"] = prevent_key_deletion
        if (key_version := _dict.get("keyVersion")) is not None:
            args["key_version"] = KeyVersion.from_dict(key_version)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RegistrationResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "key_id") and getattr(self, "key_id") is not None:
            _dict["keyId"] = getattr(self, "key_id")
        if hasattr(self, "key_name") and getattr(self, "key_name") is not None:
            _dict["keyName"] = getattr(self, "key_name")
        if hasattr(self, "resource_crn") and getattr(self, "resource_crn") is not None:
            _dict["resourceCrn"] = getattr(self, "resource_crn")
        if hasattr(self, "created_by") and getattr(self, "created_by") is not None:
            _dict["createdBy"] = getattr(self, "created_by")
        if (
            hasattr(self, "creation_date")
            and getattr(self, "creation_date") is not None
        ):
            _dict["creationDate"] = datetime_to_string(getattr(self, "creation_date"))
        if hasattr(self, "updated_by") and getattr(self, "updated_by") is not None:
            _dict["updatedBy"] = getattr(self, "updated_by")
        if hasattr(self, "last_updated") and getattr(self, "last_updated") is not None:
            _dict["lastUpdated"] = datetime_to_string(getattr(self, "last_updated"))
        if hasattr(self, "description") and getattr(self, "description") is not None:
            _dict["description"] = getattr(self, "description")
        if (
            hasattr(self, "prevent_key_deletion")
            and getattr(self, "prevent_key_deletion") is not None
        ):
            _dict["preventKeyDeletion"] = getattr(self, "prevent_key_deletion")
        if hasattr(self, "key_version") and getattr(self, "key_version") is not None:
            if isinstance(getattr(self, "key_version"), dict):
                _dict["keyVersion"] = getattr(self, "key_version")
            else:
                _dict["keyVersion"] = getattr(self, "key_version").to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RegistrationResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "RegistrationResource") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "RegistrationResource") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RegistrationWithTotalCount:
    """
    Properties associated with a list registration response which may include total
    registration count.

    :param CollectionMetadataWithTotalCount metadata: (optional) The metadata that
          describes the resource array.
    :param List[RegistrationResource] resources: (optional) A collection of
          resources.
    """

    def __init__(
        self,
        *,
        metadata: Optional["CollectionMetadataWithTotalCount"] = None,
        resources: Optional[List["RegistrationResource"]] = None,
    ) -> None:
        """
        Initialize a RegistrationWithTotalCount object.

        :param CollectionMetadataWithTotalCount metadata: (optional) The metadata
               that describes the resource array.
        :param List[RegistrationResource] resources: (optional) A collection of
               resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "RegistrationWithTotalCount":
        """Initialize a RegistrationWithTotalCount object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadataWithTotalCount.from_dict(metadata)
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [RegistrationResource.from_dict(v) for v in resources]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RegistrationWithTotalCount object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RegistrationWithTotalCount object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "RegistrationWithTotalCount") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "RegistrationWithTotalCount") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RewrapKeyResponseBody:
    """
    Properties that are associated with the response body of an rewrap action.

    :param str ciphertext: (optional) The wrapped data encryption key (WDEK) that
          you can export to your app or service. The ciphertext contains the DEK wrapped
          by the latest version of the key (WDEK). It is recommended to store and use this
          WDEK in future calls to Key Protect. The value is base64 encoded.
    :param WrappedKeyVersionKeyVersion key_version: (optional) The key version that
          was used to wrap the DEK. This key version is associated with the `ciphertext`
          value that was used in the request.
    :param RewrappedKeyVersionRewrappedKeyVersion rewrapped_key_version: (optional)
          The latest key version that was used to rewrap the DEK. This key version is
          associated with the `ciphertext` value that's returned in the response.
    """

    def __init__(
        self,
        *,
        ciphertext: Optional[str] = None,
        key_version: Optional["WrappedKeyVersionKeyVersion"] = None,
        rewrapped_key_version: Optional[
            "RewrappedKeyVersionRewrappedKeyVersion"
        ] = None,
    ) -> None:
        """
        Initialize a RewrapKeyResponseBody object.

        :param str ciphertext: (optional) The wrapped data encryption key (WDEK)
               that you can export to your app or service. The ciphertext contains the DEK
               wrapped by the latest version of the key (WDEK). It is recommended to store
               and use this WDEK in future calls to Key Protect. The value is base64
               encoded.
        """
        self.ciphertext = ciphertext
        self.key_version = key_version
        self.rewrapped_key_version = rewrapped_key_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> "RewrapKeyResponseBody":
        """Initialize a RewrapKeyResponseBody object from a json dictionary."""
        args = {}
        if (ciphertext := _dict.get("ciphertext")) is not None:
            args["ciphertext"] = ciphertext
        if (key_version := _dict.get("keyVersion")) is not None:
            args["key_version"] = WrappedKeyVersionKeyVersion.from_dict(key_version)
        if (rewrapped_key_version := _dict.get("rewrappedKeyVersion")) is not None:
            args["rewrapped_key_version"] = (
                RewrappedKeyVersionRewrappedKeyVersion.from_dict(rewrapped_key_version)
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RewrapKeyResponseBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "ciphertext") and self.ciphertext is not None:
            _dict["ciphertext"] = self.ciphertext
        if hasattr(self, "key_version") and getattr(self, "key_version") is not None:
            if isinstance(getattr(self, "key_version"), dict):
                _dict["keyVersion"] = getattr(self, "key_version")
            else:
                _dict["keyVersion"] = getattr(self, "key_version").to_dict()
        if (
            hasattr(self, "rewrapped_key_version")
            and getattr(self, "rewrapped_key_version") is not None
        ):
            if isinstance(getattr(self, "rewrapped_key_version"), dict):
                _dict["rewrappedKeyVersion"] = getattr(self, "rewrapped_key_version")
            else:
                _dict["rewrappedKeyVersion"] = getattr(
                    self, "rewrapped_key_version"
                ).to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RewrapKeyResponseBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "RewrapKeyResponseBody") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "RewrapKeyResponseBody") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RewrappedKeyVersionRewrappedKeyVersion:
    """
    The latest key version that was used to rewrap the DEK. This key version is associated
    with the `ciphertext` value that's returned in the response.

    :param str id: (optional) The ID of the key version.
    """

    def __init__(
        self,
        *,
        id: Optional[str] = None,
    ) -> None:
        """
        Initialize a RewrappedKeyVersionRewrappedKeyVersion object.

        """
        self.id = id

    @classmethod
    def from_dict(cls, _dict: Dict) -> "RewrappedKeyVersionRewrappedKeyVersion":
        """Initialize a RewrappedKeyVersionRewrappedKeyVersion object from a json dictionary."""
        args = {}
        if (id := _dict.get("id")) is not None:
            args["id"] = id
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RewrappedKeyVersionRewrappedKeyVersion object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "id") and getattr(self, "id") is not None:
            _dict["id"] = getattr(self, "id")
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RewrappedKeyVersionRewrappedKeyVersion object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "RewrappedKeyVersionRewrappedKeyVersion") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "RewrappedKeyVersionRewrappedKeyVersion") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RotationKeyMetadata:
    """
    Metadata that indicates the status of a rotation policy on the key.

    :param bool enabled: If set to `true`, Key Protect enables a rotation policy on
          a single key.
    :param int interval_month: (optional) Specifies the key rotation time interval
          in approximate months, where a month is equivalent to 30 days. A minimum of 1
          and a maximum of 12 can be set.
    """

    def __init__(
        self,
        enabled: bool,
        *,
        interval_month: Optional[int] = None,
    ) -> None:
        """
        Initialize a RotationKeyMetadata object.

        :param bool enabled: If set to `true`, Key Protect enables a rotation
               policy on a single key.
        :param int interval_month: (optional) Specifies the key rotation time
               interval in approximate months, where a month is equivalent to 30 days. A
               minimum of 1 and a maximum of 12 can be set.
        """
        self.enabled = enabled
        self.interval_month = interval_month

    @classmethod
    def from_dict(cls, _dict: Dict) -> "RotationKeyMetadata":
        """Initialize a RotationKeyMetadata object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            args["enabled"] = None
        if (interval_month := _dict.get("interval_month")) is not None:
            args["interval_month"] = interval_month
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RotationKeyMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        if hasattr(self, "interval_month") and self.interval_month is not None:
            _dict["interval_month"] = self.interval_month
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RotationKeyMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "RotationKeyMetadata") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "RotationKeyMetadata") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SetInstancePoliciesOneOf:
    """
    SetInstancePoliciesOneOf.

    """

    def __init__(
        self,
    ) -> None:
        """
        Initialize a SetInstancePoliciesOneOf object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(
                [
                    "SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork",
                    "SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete",
                    "SetInstancePoliciesOneOfSetInstancePolicyAllowedIP",
                    "SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess",
                    "SetInstancePoliciesOneOfSetInstancePolicyMetrics",
                    "SetInstancePoliciesOneOfSetInstancePolicyRotation",
                    "SetInstancePoliciesOneOfSetMultipleInstancePolicies",
                ]
            )
        )
        raise Exception(msg)


class SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem:
    """
    SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem.

    :param str policy_type: The type of policy to be set.
    :param InstancePolicyAllowedIPPolicyData policy_data: User defined metadata that
          is associated with the `allowedIP` instance policy type.
    """

    def __init__(
        self,
        policy_type: str,
        policy_data: "InstancePolicyAllowedIPPolicyData",
    ) -> None:
        """
        Initialize a SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem object.

        :param str policy_type: The type of policy to be set.
        :param InstancePolicyAllowedIPPolicyData policy_data: User defined metadata
               that is associated with the `allowedIP` instance policy type.
        """
        self.policy_type = policy_type
        self.policy_data = policy_data

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem":
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem object from a json dictionary."""
        args = {}
        if (policy_type := _dict.get("policy_type")) is not None:
            args["policy_type"] = policy_type
        else:
            raise ValueError(
                "Required property 'policy_type' not present in SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem JSON"
            )
        if (policy_data := _dict.get("policy_data")) is not None:
            args["policy_data"] = InstancePolicyAllowedIPPolicyData.from_dict(
                policy_data
            )
        else:
            raise ValueError(
                "Required property 'policy_data' not present in SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "policy_type") and self.policy_type is not None:
            _dict["policy_type"] = self.policy_type
        if hasattr(self, "policy_data") and self.policy_data is not None:
            if isinstance(self.policy_data, dict):
                _dict["policy_data"] = self.policy_data
            else:
                _dict["policy_data"] = self.policy_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class PolicyTypeEnum(str, Enum):
        """
        The type of policy to be set.
        """

        ALLOWEDIP = "allowedIP"


class SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem:
    """
    SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem.

    :param str policy_type: The type of policy to be set.
    :param InstancePolicyAllowedNetworkPolicyData policy_data: User defined metadata
          that is associated with the `allowedNetwork` instance policy type.
    """

    def __init__(
        self,
        policy_type: str,
        policy_data: "InstancePolicyAllowedNetworkPolicyData",
    ) -> None:
        """
        Initialize a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem object.

        :param str policy_type: The type of policy to be set.
        :param InstancePolicyAllowedNetworkPolicyData policy_data: User defined
               metadata that is associated with the `allowedNetwork` instance policy type.
        """
        self.policy_type = policy_type
        self.policy_data = policy_data

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem":
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem object from a json dictionary."""
        args = {}
        if (policy_type := _dict.get("policy_type")) is not None:
            args["policy_type"] = policy_type
        else:
            raise ValueError(
                "Required property 'policy_type' not present in SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem JSON"
            )
        if (policy_data := _dict.get("policy_data")) is not None:
            args["policy_data"] = InstancePolicyAllowedNetworkPolicyData.from_dict(
                policy_data
            )
        else:
            raise ValueError(
                "Required property 'policy_data' not present in SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "policy_type") and self.policy_type is not None:
            _dict["policy_type"] = self.policy_type
        if hasattr(self, "policy_data") and self.policy_data is not None:
            if isinstance(self.policy_data, dict):
                _dict["policy_data"] = self.policy_data
            else:
                _dict["policy_data"] = self.policy_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self,
        other: "SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem",
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self,
        other: "SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem",
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class PolicyTypeEnum(str, Enum):
        """
        The type of policy to be set.
        """

        ALLOWEDNETWORK = "allowedNetwork"


class SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem:
    """
    SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem.

    :param str policy_type: The type of policy to be set.
    :param InstancePolicyKeyCreateImportAccessPolicyData policy_data: User defined
          metadata that is associated with the `keyCreateImportAccess` instance policy
          type.
    """

    def __init__(
        self,
        policy_type: str,
        policy_data: "InstancePolicyKeyCreateImportAccessPolicyData",
    ) -> None:
        """
        Initialize a SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem object.

        :param str policy_type: The type of policy to be set.
        :param InstancePolicyKeyCreateImportAccessPolicyData policy_data: User
               defined metadata that is associated with the `keyCreateImportAccess`
               instance policy type.
        """
        self.policy_type = policy_type
        self.policy_data = policy_data

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem":
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem object from a json dictionary."""
        args = {}
        if (policy_type := _dict.get("policy_type")) is not None:
            args["policy_type"] = policy_type
        else:
            raise ValueError(
                "Required property 'policy_type' not present in SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem JSON"
            )
        if (policy_data := _dict.get("policy_data")) is not None:
            args["policy_data"] = (
                InstancePolicyKeyCreateImportAccessPolicyData.from_dict(policy_data)
            )
        else:
            raise ValueError(
                "Required property 'policy_data' not present in SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "policy_type") and self.policy_type is not None:
            _dict["policy_type"] = self.policy_type
        if hasattr(self, "policy_data") and self.policy_data is not None:
            if isinstance(self.policy_data, dict):
                _dict["policy_data"] = self.policy_data
            else:
                _dict["policy_data"] = self.policy_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self,
        other: "SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem",
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self,
        other: "SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem",
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class PolicyTypeEnum(str, Enum):
        """
        The type of policy to be set.
        """

        KEYCREATEIMPORTACCESS = "keyCreateImportAccess"


class SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem:
    """
    SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem.

    :param str policy_type: The type of policy to be set.
    :param MetricsProperties policy_data: User defined metadata that is associated
          with the `metrics` instance policy type.
    """

    def __init__(
        self,
        policy_type: str,
        policy_data: "MetricsProperties",
    ) -> None:
        """
        Initialize a SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem object.

        :param str policy_type: The type of policy to be set.
        :param MetricsProperties policy_data: User defined metadata that is
               associated with the `metrics` instance policy type.
        """
        self.policy_type = policy_type
        self.policy_data = policy_data

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem":
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem object from a json dictionary."""
        args = {}
        if (policy_type := _dict.get("policy_type")) is not None:
            args["policy_type"] = policy_type
        else:
            raise ValueError(
                "Required property 'policy_type' not present in SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem JSON"
            )
        if (policy_data := _dict.get("policy_data")) is not None:
            args["policy_data"] = MetricsProperties.from_dict(policy_data)
        else:
            raise ValueError(
                "Required property 'policy_data' not present in SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "policy_type") and self.policy_type is not None:
            _dict["policy_type"] = self.policy_type
        if hasattr(self, "policy_data") and self.policy_data is not None:
            if isinstance(self.policy_data, dict):
                _dict["policy_data"] = self.policy_data
            else:
                _dict["policy_data"] = self.policy_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class PolicyTypeEnum(str, Enum):
        """
        The type of policy to be set.
        """

        METRICS = "metrics"


class SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem:
    """
    SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem.

    :param str policy_type: The type of policy to be set.
    :param InstancePolicyRotationPolicyData policy_data: User defined metadata that
          is associated with the `rotation` instance policy type.
    """

    def __init__(
        self,
        policy_type: str,
        policy_data: "InstancePolicyRotationPolicyData",
    ) -> None:
        """
        Initialize a SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem object.

        :param str policy_type: The type of policy to be set.
        :param InstancePolicyRotationPolicyData policy_data: User defined metadata
               that is associated with the `rotation` instance policy type.
        """
        self.policy_type = policy_type
        self.policy_data = policy_data

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem":
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem object from a json dictionary."""
        args = {}
        if (policy_type := _dict.get("policy_type")) is not None:
            args["policy_type"] = policy_type
        else:
            raise ValueError(
                "Required property 'policy_type' not present in SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem JSON"
            )
        if (policy_data := _dict.get("policy_data")) is not None:
            args["policy_data"] = InstancePolicyRotationPolicyData.from_dict(
                policy_data
            )
        else:
            raise ValueError(
                "Required property 'policy_data' not present in SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "policy_type") and self.policy_type is not None:
            _dict["policy_type"] = self.policy_type
        if hasattr(self, "policy_data") and self.policy_data is not None:
            if isinstance(self.policy_data, dict):
                _dict["policy_data"] = self.policy_data
            else:
                _dict["policy_data"] = self.policy_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class PolicyTypeEnum(str, Enum):
        """
        The type of policy to be set.
        """

        ROTATION = "rotation"


class SetInstancePolicyDualAuthDeleteResourcesItem:
    """
    SetInstancePolicyDualAuthDeleteResourcesItem.

    :param str policy_type: The type of policy to be set.
    :param DualAuthDeleteProperties policy_data: User defined metadata that is
          associated with the `dualAuthDelete` instance policy type.
    """

    def __init__(
        self,
        policy_type: str,
        policy_data: "DualAuthDeleteProperties",
    ) -> None:
        """
        Initialize a SetInstancePolicyDualAuthDeleteResourcesItem object.

        :param str policy_type: The type of policy to be set.
        :param DualAuthDeleteProperties policy_data: User defined metadata that is
               associated with the `dualAuthDelete` instance policy type.
        """
        self.policy_type = policy_type
        self.policy_data = policy_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> "SetInstancePolicyDualAuthDeleteResourcesItem":
        """Initialize a SetInstancePolicyDualAuthDeleteResourcesItem object from a json dictionary."""
        args = {}
        if (policy_type := _dict.get("policy_type")) is not None:
            args["policy_type"] = policy_type
        else:
            raise ValueError(
                "Required property 'policy_type' not present in SetInstancePolicyDualAuthDeleteResourcesItem JSON"
            )
        if (policy_data := _dict.get("policy_data")) is not None:
            args["policy_data"] = DualAuthDeleteProperties.from_dict(policy_data)
        else:
            raise ValueError(
                "Required property 'policy_data' not present in SetInstancePolicyDualAuthDeleteResourcesItem JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetInstancePolicyDualAuthDeleteResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "policy_type") and self.policy_type is not None:
            _dict["policy_type"] = self.policy_type
        if hasattr(self, "policy_data") and self.policy_data is not None:
            if isinstance(self.policy_data, dict):
                _dict["policy_data"] = self.policy_data
            else:
                _dict["policy_data"] = self.policy_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetInstancePolicyDualAuthDeleteResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "SetInstancePolicyDualAuthDeleteResourcesItem") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "SetInstancePolicyDualAuthDeleteResourcesItem") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class PolicyTypeEnum(str, Enum):
        """
        The type of policy to be set.
        """

        DUALAUTHDELETE = "dualAuthDelete"


class SetKeyPoliciesOneOf:
    """
    SetKeyPoliciesOneOf.

    """

    def __init__(
        self,
    ) -> None:
        """
        Initialize a SetKeyPoliciesOneOf object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(
                [
                    "SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete",
                    "SetKeyPoliciesOneOfSetKeyPolicyRotation",
                    "SetKeyPoliciesOneOfSetMultipleKeyPolicies",
                ]
            )
        )
        raise Exception(msg)


class SetMultipleInstancePoliciesResourcesItem:
    """
    SetMultipleInstancePoliciesResourcesItem.

    :param str policy_type: The type of policy to be set.
    :param SetMultipleInstancePoliciesResourcesItemPolicyData policy_data: User
          defined metadata that is associated with any instance policy.
    """

    def __init__(
        self,
        policy_type: str,
        policy_data: "SetMultipleInstancePoliciesResourcesItemPolicyData",
    ) -> None:
        """
        Initialize a SetMultipleInstancePoliciesResourcesItem object.

        :param str policy_type: The type of policy to be set.
        :param SetMultipleInstancePoliciesResourcesItemPolicyData policy_data: User
               defined metadata that is associated with any instance policy.
        """
        self.policy_type = policy_type
        self.policy_data = policy_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> "SetMultipleInstancePoliciesResourcesItem":
        """Initialize a SetMultipleInstancePoliciesResourcesItem object from a json dictionary."""
        args = {}
        if (policy_type := _dict.get("policy_type")) is not None:
            args["policy_type"] = policy_type
        else:
            raise ValueError(
                "Required property 'policy_type' not present in SetMultipleInstancePoliciesResourcesItem JSON"
            )
        if (policy_data := _dict.get("policy_data")) is not None:
            args["policy_data"] = (
                SetMultipleInstancePoliciesResourcesItemPolicyData.from_dict(
                    policy_data
                )
            )
        else:
            args["policy_data"] = None
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetMultipleInstancePoliciesResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "policy_type") and self.policy_type is not None:
            _dict["policy_type"] = self.policy_type
        if hasattr(self, "policy_data") and self.policy_data is not None:
            if isinstance(self.policy_data, dict):
                _dict["policy_data"] = self.policy_data
            else:
                _dict["policy_data"] = self.policy_data.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetMultipleInstancePoliciesResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "SetMultipleInstancePoliciesResourcesItem") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "SetMultipleInstancePoliciesResourcesItem") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class PolicyTypeEnum(str, Enum):
        """
        The type of policy to be set.
        """

        ALLOWEDNETWORK = "allowedNetwork"
        DUALAUTHDELETE = "dualAuthDelete"
        ALLOWEDIP = "allowedIP"
        KEYCREATEIMPORTACCESS = "keyCreateImportAccess"
        METRICS = "metrics"
        ROTATION = "rotation"


class SetMultipleInstancePoliciesResourcesItemPolicyData:
    """
    User defined metadata that is associated with any instance policy.

    :param bool enabled: If set to `true`, Key Protect enables the specified policy
          for your service instance. If set to `false`, Key Protect disables the specified
          policy for your service instance, and the policy will no longer affect Key
          Protect actions.
          **Note:** If a policy with attributes is disabled, all attributes are reset and
          are not retained.
    :param SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes attributes:
          (optional) Attributes associated with any instance policy type. Must be provided
          if the `enabled` field is `true`. Cannot be provided if the `enabled` field is
          `false`. Only attributes corresponding to the `policy_type` can be provided.
    """

    def __init__(
        self,
        enabled: bool,
        *,
        attributes: Optional[
            "SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes"
        ] = None,
    ) -> None:
        """
        Initialize a SetMultipleInstancePoliciesResourcesItemPolicyData object.

        :param bool enabled: If set to `true`, Key Protect enables the specified
               policy for your service instance. If set to `false`, Key Protect disables
               the specified policy for your service instance, and the policy will no
               longer affect Key Protect actions.
               **Note:** If a policy with attributes is disabled, all attributes are reset
               and are not retained.
        :param SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes
               attributes: (optional) Attributes associated with any instance policy type.
               Must be provided if the `enabled` field is `true`. Cannot be provided if
               the `enabled` field is `false`. Only attributes corresponding to the
               `policy_type` can be provided.
        """
        self.enabled = enabled
        self.attributes = attributes

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "SetMultipleInstancePoliciesResourcesItemPolicyData":
        """Initialize a SetMultipleInstancePoliciesResourcesItemPolicyData object from a json dictionary."""
        args = {}
        if (enabled := _dict.get("enabled")) is not None:
            args["enabled"] = enabled
        else:
            args["enabled"] = None
        if (attributes := _dict.get("attributes")) is not None:
            args["attributes"] = (
                SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes.from_dict(
                    attributes
                )
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetMultipleInstancePoliciesResourcesItemPolicyData object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "enabled") and self.enabled is not None:
            _dict["enabled"] = self.enabled
        if hasattr(self, "attributes") and self.attributes is not None:
            if isinstance(self.attributes, dict):
                _dict["attributes"] = self.attributes
            else:
                _dict["attributes"] = self.attributes.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetMultipleInstancePoliciesResourcesItemPolicyData object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "SetMultipleInstancePoliciesResourcesItemPolicyData"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "SetMultipleInstancePoliciesResourcesItemPolicyData"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes:
    """
    Attributes associated with any instance policy type. Must be provided if the `enabled`
    field is `true`. Cannot be provided if the `enabled` field is `false`. Only attributes
    corresponding to the `policy_type` can be provided.

    :param str allowed_network: (optional) If set to `public-and-private`, Key
          Protect allows the instance to be accessible through public and private
          endpoints. If set to `private-only`, Key Protect restricts the instance to only
          be accessible through a private endpoint.
    :param List[str] allowed_ip: (optional) A string array of IPv4 or IPv6 CIDR
          notated subnets that are authorized to interact with the instance. If both
          `allowedNetwork` and `allowedIP` policies are set, only traffic aligning with
          both the `allowed_network` allowed network policy attribute and the `allowed_ip`
          allowed IP policy attribute will be allowed. IPv4 and iIP6 addresses are
          accepted for public endpoints. Only the IPv4 private network gateway addresses
          from the array will be authorized to access your instance via private endpoint.
          **Important:** Once set, accessing your instance may require additional steps.
          For more information, see [Accessing an instance via public
          endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-public-endpoint)
          and [Accessing an instance via private
          endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-private-endpoint)
          for more details.
          **Note:** An allowed IP policy does not affect requests from other IBM Cloud
          services.
    :param bool create_root_key: (optional) If set to `false`, the service prevents
          you or any authorized users from using Key Protect to create root keys in the
          specified service instance. If set to `true`, Key Protect allows you or any
          authorized users to create root keys in the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool create_standard_key: (optional) If set to `false`, the service
          prevents you or any authorized users from using Key Protect to create standard
          keys in the specified service instance. If set to `true`, Key Protect allows you
          or any authorized users to create standard keys in the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool import_root_key: (optional) If set to `false`, the service prevents
          you or any authorized users from importing root keys into the specified service
          instance. If set to `true`, Key Protect allows you or any authorized users to
          import root keys into the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool import_standard_key: (optional) If set to `false`, the service
          prevents you or any authorized users from importing standard keys into the
          specified service instance. If set to `true`, Key Protect allows you or any
          authorized users to import standard keys into the instance.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`true`).
    :param bool enforce_token: (optional) If set to `true`, the service prevents you
          or any authorized users from importing key material into the specified service
          instance without using an import token. If set to `false`, Key Protect allows
          you or any authorized users to import key material into the instance without the
          use of an import token.
          **Note:** If omitted, `POST /instance/policies` will set this attribute to the
          default value (`false`).
    :param int interval_month: (optional) Specifies the key rotation time interval
          in approximate months, where a month is equivalent to 30 days. A minimum of 1
          and a maximum of 12 can be set.
    """

    def __init__(
        self,
        *,
        allowed_network: Optional[str] = None,
        allowed_ip: Optional[List[str]] = None,
        create_root_key: Optional[bool] = None,
        create_standard_key: Optional[bool] = None,
        import_root_key: Optional[bool] = None,
        import_standard_key: Optional[bool] = None,
        enforce_token: Optional[bool] = None,
        interval_month: Optional[int] = None,
    ) -> None:
        """
        Initialize a SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes object.

        :param str allowed_network: (optional) If set to `public-and-private`, Key
               Protect allows the instance to be accessible through public and private
               endpoints. If set to `private-only`, Key Protect restricts the instance to
               only be accessible through a private endpoint.
        :param List[str] allowed_ip: (optional) A string array of IPv4 or IPv6 CIDR
               notated subnets that are authorized to interact with the instance. If both
               `allowedNetwork` and `allowedIP` policies are set, only traffic aligning
               with both the `allowed_network` allowed network policy attribute and the
               `allowed_ip` allowed IP policy attribute will be allowed. IPv4 and iIP6
               addresses are accepted for public endpoints. Only the IPv4 private network
               gateway addresses from the array will be authorized to access your instance
               via private endpoint.
               **Important:** Once set, accessing your instance may require additional
               steps. For more information, see [Accessing an instance via public
               endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-public-endpoint)
               and [Accessing an instance via private
               endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-private-endpoint)
               for more details.
               **Note:** An allowed IP policy does not affect requests from other IBM
               Cloud services.
        :param bool create_root_key: (optional) If set to `false`, the service
               prevents you or any authorized users from using Key Protect to create root
               keys in the specified service instance. If set to `true`, Key Protect
               allows you or any authorized users to create root keys in the instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool create_standard_key: (optional) If set to `false`, the service
               prevents you or any authorized users from using Key Protect to create
               standard keys in the specified service instance. If set to `true`, Key
               Protect allows you or any authorized users to create standard keys in the
               instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool import_root_key: (optional) If set to `false`, the service
               prevents you or any authorized users from importing root keys into the
               specified service instance. If set to `true`, Key Protect allows you or any
               authorized users to import root keys into the instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool import_standard_key: (optional) If set to `false`, the service
               prevents you or any authorized users from importing standard keys into the
               specified service instance. If set to `true`, Key Protect allows you or any
               authorized users to import standard keys into the instance.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`true`).
        :param bool enforce_token: (optional) If set to `true`, the service
               prevents you or any authorized users from importing key material into the
               specified service instance without using an import token. If set to
               `false`, Key Protect allows you or any authorized users to import key
               material into the instance without the use of an import token.
               **Note:** If omitted, `POST /instance/policies` will set this attribute to
               the default value (`false`).
        :param int interval_month: (optional) Specifies the key rotation time
               interval in approximate months, where a month is equivalent to 30 days. A
               minimum of 1 and a maximum of 12 can be set.
        """
        self.allowed_network = allowed_network
        self.allowed_ip = allowed_ip
        self.create_root_key = create_root_key
        self.create_standard_key = create_standard_key
        self.import_root_key = import_root_key
        self.import_standard_key = import_standard_key
        self.enforce_token = enforce_token
        self.interval_month = interval_month

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes":
        """Initialize a SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes object from a json dictionary."""
        args = {}
        if (allowed_network := _dict.get("allowed_network")) is not None:
            args["allowed_network"] = allowed_network
        if (allowed_ip := _dict.get("allowed_ip")) is not None:
            args["allowed_ip"] = allowed_ip
        if (create_root_key := _dict.get("create_root_key")) is not None:
            args["create_root_key"] = create_root_key
        if (create_standard_key := _dict.get("create_standard_key")) is not None:
            args["create_standard_key"] = create_standard_key
        if (import_root_key := _dict.get("import_root_key")) is not None:
            args["import_root_key"] = import_root_key
        if (import_standard_key := _dict.get("import_standard_key")) is not None:
            args["import_standard_key"] = import_standard_key
        if (enforce_token := _dict.get("enforce_token")) is not None:
            args["enforce_token"] = enforce_token
        if (interval_month := _dict.get("interval_month")) is not None:
            args["interval_month"] = interval_month
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "allowed_network") and self.allowed_network is not None:
            _dict["allowed_network"] = self.allowed_network
        if hasattr(self, "allowed_ip") and self.allowed_ip is not None:
            _dict["allowed_ip"] = self.allowed_ip
        if hasattr(self, "create_root_key") and self.create_root_key is not None:
            _dict["create_root_key"] = self.create_root_key
        if (
            hasattr(self, "create_standard_key")
            and self.create_standard_key is not None
        ):
            _dict["create_standard_key"] = self.create_standard_key
        if hasattr(self, "import_root_key") and self.import_root_key is not None:
            _dict["import_root_key"] = self.import_root_key
        if (
            hasattr(self, "import_standard_key")
            and self.import_standard_key is not None
        ):
            _dict["import_standard_key"] = self.import_standard_key
        if hasattr(self, "enforce_token") and self.enforce_token is not None:
            _dict["enforce_token"] = self.enforce_token
        if hasattr(self, "interval_month") and self.interval_month is not None:
            _dict["interval_month"] = self.interval_month
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class AllowedNetworkEnum(str, Enum):
        """
        If set to `public-and-private`, Key Protect allows the instance to be accessible
        through public and private endpoints. If set to `private-only`, Key Protect
        restricts the instance to only be accessible through a private endpoint.
        """

        PUBLIC_AND_PRIVATE = "public-and-private"
        PRIVATE_ONLY = "private-only"


class SetMultipleKeyPoliciesResource:
    """
    Properties that are associated with key level dual authorization delete policy.

    :param str type: Specifies the MIME type that represents the policy resource.
          Currently, only the default is supported.
    :param KeyPolicyDualAuthDeleteDualAuthDelete dual_auth_delete: Data associated
          with the dual authorization delete policy.
    :param KeyPolicyRotationRotation rotation: Data associated with the automatic
          key rotation policy.
    """

    def __init__(
        self,
        type: str,
        dual_auth_delete: "KeyPolicyDualAuthDeleteDualAuthDelete",
        rotation: "KeyPolicyRotationRotation",
    ) -> None:
        """
        Initialize a SetMultipleKeyPoliciesResource object.

        :param str type: Specifies the MIME type that represents the policy
               resource. Currently, only the default is supported.
        :param KeyPolicyDualAuthDeleteDualAuthDelete dual_auth_delete: Data
               associated with the dual authorization delete policy.
        :param KeyPolicyRotationRotation rotation: Data associated with the
               automatic key rotation policy.
        """
        self.type = type
        self.dual_auth_delete = dual_auth_delete
        self.rotation = rotation

    @classmethod
    def from_dict(cls, _dict: Dict) -> "SetMultipleKeyPoliciesResource":
        """Initialize a SetMultipleKeyPoliciesResource object from a json dictionary."""
        args = {}
        if (type := _dict.get("type")) is not None:
            args["type"] = type
        else:
            raise ValueError(
                "Required property 'type' not present in SetMultipleKeyPoliciesResource JSON"
            )
        if (dual_auth_delete := _dict.get("dualAuthDelete")) is not None:
            args["dual_auth_delete"] = KeyPolicyDualAuthDeleteDualAuthDelete.from_dict(
                dual_auth_delete
            )
        else:
            args["dual_auth_delete"] = None
        if (rotation := _dict.get("rotation")) is not None:
            args["rotation"] = KeyPolicyRotationRotation.from_dict(rotation)
        else:
            args["rotation"] = None
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetMultipleKeyPoliciesResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "type") and self.type is not None:
            _dict["type"] = self.type
        if hasattr(self, "dual_auth_delete") and self.dual_auth_delete is not None:
            if isinstance(self.dual_auth_delete, dict):
                _dict["dualAuthDelete"] = self.dual_auth_delete
            else:
                _dict["dualAuthDelete"] = self.dual_auth_delete.to_dict()
        if hasattr(self, "rotation") and self.rotation is not None:
            if isinstance(self.rotation, dict):
                _dict["rotation"] = self.rotation
            else:
                _dict["rotation"] = self.rotation.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetMultipleKeyPoliciesResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "SetMultipleKeyPoliciesResource") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "SetMultipleKeyPoliciesResource") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        Specifies the MIME type that represents the policy resource. Currently, only the
        default is supported.
        """

        APPLICATION_VND_IBM_KMS_POLICY_JSON = "application/vnd.ibm.kms.policy+json"


class UnwrapKeyResponseBody:
    """
    Properties that are associated with the response body of an unwrap action.

    :param str plaintext: (optional) The data encryption key (DEK) used in wrap
          actions when the query parameter is set to `wrap`. The system returns a base64
          encoded plaintext in the response entity-body when you perform an `unwrap`
          action on a key. To wrap an existing DEK, provide a base64 encoded plaintext
          during a `wrap` action. To generate a new DEK, omit the `plaintext` property.
          Key Protect generates a random plaintext (32 bytes) that is rooted in an HSM and
          then wraps that value.
          **Note:** When you unwrap a wrapped data encryption key (WDEK) by using a
          rotated root key, the service returns a new ciphertext in the response
          entity-body. Each ciphertext remains available for `unwrap` actions. If you
          unwrap a DEK with a previous ciphertext, the service also returns the latest
          ciphertext in the response. Use the latest ciphertext for future unwrap
          operations.
    :param str ciphertext: (optional) The wrapped data encryption key (WDEK) that
          you can export to your app or service. The ciphertext contains the DEK wrapped
          by the latest version of the key (WDEK). It is recommended to store and use this
          WDEK in future calls to Key Protect. The value is base64 encoded.
    :param WrappedKeyVersionKeyVersion key_version: (optional) The key version that
          was used to wrap the DEK. This key version is associated with the `ciphertext`
          value that was used in the request.
    :param RewrappedKeyVersionRewrappedKeyVersion rewrapped_key_version: (optional)
          The latest key version that was used to rewrap the DEK. This key version is
          associated with the `ciphertext` value that's returned in the response.
    """

    def __init__(
        self,
        *,
        plaintext: Optional[str] = None,
        ciphertext: Optional[str] = None,
        key_version: Optional["WrappedKeyVersionKeyVersion"] = None,
        rewrapped_key_version: Optional[
            "RewrappedKeyVersionRewrappedKeyVersion"
        ] = None,
    ) -> None:
        """
        Initialize a UnwrapKeyResponseBody object.

        :param str plaintext: (optional) The data encryption key (DEK) used in wrap
               actions when the query parameter is set to `wrap`. The system returns a
               base64 encoded plaintext in the response entity-body when you perform an
               `unwrap` action on a key. To wrap an existing DEK, provide a base64 encoded
               plaintext during a `wrap` action. To generate a new DEK, omit the
               `plaintext` property. Key Protect generates a random plaintext (32 bytes)
               that is rooted in an HSM and then wraps that value.
               **Note:** When you unwrap a wrapped data encryption key (WDEK) by using a
               rotated root key, the service returns a new ciphertext in the response
               entity-body. Each ciphertext remains available for `unwrap` actions. If you
               unwrap a DEK with a previous ciphertext, the service also returns the
               latest ciphertext in the response. Use the latest ciphertext for future
               unwrap operations.
        :param str ciphertext: (optional) The wrapped data encryption key (WDEK)
               that you can export to your app or service. The ciphertext contains the DEK
               wrapped by the latest version of the key (WDEK). It is recommended to store
               and use this WDEK in future calls to Key Protect. The value is base64
               encoded.
        """
        self.plaintext = plaintext
        self.ciphertext = ciphertext
        self.key_version = key_version
        self.rewrapped_key_version = rewrapped_key_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> "UnwrapKeyResponseBody":
        """Initialize a UnwrapKeyResponseBody object from a json dictionary."""
        args = {}
        if (plaintext := _dict.get("plaintext")) is not None:
            args["plaintext"] = plaintext
        if (ciphertext := _dict.get("ciphertext")) is not None:
            args["ciphertext"] = ciphertext
        if (key_version := _dict.get("keyVersion")) is not None:
            args["key_version"] = WrappedKeyVersionKeyVersion.from_dict(key_version)
        if (rewrapped_key_version := _dict.get("rewrappedKeyVersion")) is not None:
            args["rewrapped_key_version"] = (
                RewrappedKeyVersionRewrappedKeyVersion.from_dict(rewrapped_key_version)
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UnwrapKeyResponseBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "plaintext") and self.plaintext is not None:
            _dict["plaintext"] = self.plaintext
        if hasattr(self, "ciphertext") and self.ciphertext is not None:
            _dict["ciphertext"] = self.ciphertext
        if hasattr(self, "key_version") and getattr(self, "key_version") is not None:
            if isinstance(getattr(self, "key_version"), dict):
                _dict["keyVersion"] = getattr(self, "key_version")
            else:
                _dict["keyVersion"] = getattr(self, "key_version").to_dict()
        if (
            hasattr(self, "rewrapped_key_version")
            and getattr(self, "rewrapped_key_version") is not None
        ):
            if isinstance(getattr(self, "rewrapped_key_version"), dict):
                _dict["rewrappedKeyVersion"] = getattr(self, "rewrapped_key_version")
            else:
                _dict["rewrappedKeyVersion"] = getattr(
                    self, "rewrapped_key_version"
                ).to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this UnwrapKeyResponseBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "UnwrapKeyResponseBody") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "UnwrapKeyResponseBody") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class WrapKeyResponseBody:
    """
    Properties that are associated with the response body of a wrap action.

    :param str plaintext: (optional) The data encryption key (DEK) used in wrap
          actions when the query parameter is set to `wrap`. The system returns a base64
          encoded plaintext in the response entity-body when you perform an `unwrap`
          action on a key. To wrap an existing DEK, provide a base64 encoded plaintext
          during a `wrap` action. To generate a new DEK, omit the `plaintext` property.
          Key Protect generates a random plaintext (32 bytes) that is rooted in an HSM and
          then wraps that value.
          **Note:** When you unwrap a wrapped data encryption key (WDEK) by using a
          rotated root key, the service returns a new ciphertext in the response
          entity-body. Each ciphertext remains available for `unwrap` actions. If you
          unwrap a DEK with a previous ciphertext, the service also returns the latest
          ciphertext in the response. Use the latest ciphertext for future unwrap
          operations.
    :param str ciphertext: (optional) The wrapped data encryption key (WDEK) that
          you can export to your app or service. The ciphertext contains the DEK wrapped
          by the latest version of the key (WDEK). It is recommended to store and use this
          WDEK in future calls to Key Protect. The value is base64 encoded.
    :param WrappedKeyVersionKeyVersion key_version: (optional) The key version that
          was used to wrap the DEK. This key version is associated with the `ciphertext`
          value that was used in the request.
    """

    def __init__(
        self,
        *,
        plaintext: Optional[str] = None,
        ciphertext: Optional[str] = None,
        key_version: Optional["WrappedKeyVersionKeyVersion"] = None,
    ) -> None:
        """
        Initialize a WrapKeyResponseBody object.

        :param str plaintext: (optional) The data encryption key (DEK) used in wrap
               actions when the query parameter is set to `wrap`. The system returns a
               base64 encoded plaintext in the response entity-body when you perform an
               `unwrap` action on a key. To wrap an existing DEK, provide a base64 encoded
               plaintext during a `wrap` action. To generate a new DEK, omit the
               `plaintext` property. Key Protect generates a random plaintext (32 bytes)
               that is rooted in an HSM and then wraps that value.
               **Note:** When you unwrap a wrapped data encryption key (WDEK) by using a
               rotated root key, the service returns a new ciphertext in the response
               entity-body. Each ciphertext remains available for `unwrap` actions. If you
               unwrap a DEK with a previous ciphertext, the service also returns the
               latest ciphertext in the response. Use the latest ciphertext for future
               unwrap operations.
        :param str ciphertext: (optional) The wrapped data encryption key (WDEK)
               that you can export to your app or service. The ciphertext contains the DEK
               wrapped by the latest version of the key (WDEK). It is recommended to store
               and use this WDEK in future calls to Key Protect. The value is base64
               encoded.
        """
        self.plaintext = plaintext
        self.ciphertext = ciphertext
        self.key_version = key_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> "WrapKeyResponseBody":
        """Initialize a WrapKeyResponseBody object from a json dictionary."""
        args = {}
        if (plaintext := _dict.get("plaintext")) is not None:
            args["plaintext"] = plaintext
        if (ciphertext := _dict.get("ciphertext")) is not None:
            args["ciphertext"] = ciphertext
        if (key_version := _dict.get("keyVersion")) is not None:
            args["key_version"] = WrappedKeyVersionKeyVersion.from_dict(key_version)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a WrapKeyResponseBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "plaintext") and self.plaintext is not None:
            _dict["plaintext"] = self.plaintext
        if hasattr(self, "ciphertext") and self.ciphertext is not None:
            _dict["ciphertext"] = self.ciphertext
        if hasattr(self, "key_version") and getattr(self, "key_version") is not None:
            if isinstance(getattr(self, "key_version"), dict):
                _dict["keyVersion"] = getattr(self, "key_version")
            else:
                _dict["keyVersion"] = getattr(self, "key_version").to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this WrapKeyResponseBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "WrapKeyResponseBody") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "WrapKeyResponseBody") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class WrappedKeyVersionKeyVersion:
    """
    The key version that was used to wrap the DEK. This key version is associated with the
    `ciphertext` value that was used in the request.

    :param str id: (optional) The ID of the key version.
    """

    def __init__(
        self,
        *,
        id: Optional[str] = None,
    ) -> None:
        """
        Initialize a WrappedKeyVersionKeyVersion object.

        """
        self.id = id

    @classmethod
    def from_dict(cls, _dict: Dict) -> "WrappedKeyVersionKeyVersion":
        """Initialize a WrappedKeyVersionKeyVersion object from a json dictionary."""
        args = {}
        if (id := _dict.get("id")) is not None:
            args["id"] = id
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a WrappedKeyVersionKeyVersion object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "id") and getattr(self, "id") is not None:
            _dict["id"] = getattr(self, "id")
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this WrappedKeyVersionKeyVersion object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "WrappedKeyVersionKeyVersion") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "WrappedKeyVersionKeyVersion") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CollectionMetadataOneOfCollectionMetadata(CollectionMetadataOneOf):
    """
    The metadata that describes the resource array.

    :param str collection_type: The type of resources in the resource array.
    :param int collection_total: The number of elements in the resource array.
    """

    def __init__(
        self,
        collection_type: str,
        collection_total: int,
    ) -> None:
        """
        Initialize a CollectionMetadataOneOfCollectionMetadata object.

        :param str collection_type: The type of resources in the resource array.
        :param int collection_total: The number of elements in the resource array.
        """
        # pylint: disable=super-init-not-called
        self.collection_type = collection_type
        self.collection_total = collection_total

    @classmethod
    def from_dict(cls, _dict: Dict) -> "CollectionMetadataOneOfCollectionMetadata":
        """Initialize a CollectionMetadataOneOfCollectionMetadata object from a json dictionary."""
        args = {}
        if (collection_type := _dict.get("collectionType")) is not None:
            args["collection_type"] = collection_type
        else:
            raise ValueError(
                "Required property 'collectionType' not present in CollectionMetadataOneOfCollectionMetadata JSON"
            )
        if (collection_total := _dict.get("collectionTotal")) is not None:
            args["collection_total"] = collection_total
        else:
            raise ValueError(
                "Required property 'collectionTotal' not present in CollectionMetadataOneOfCollectionMetadata JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CollectionMetadataOneOfCollectionMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "collection_type") and self.collection_type is not None:
            _dict["collectionType"] = self.collection_type
        if hasattr(self, "collection_total") and self.collection_total is not None:
            _dict["collectionTotal"] = self.collection_total
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CollectionMetadataOneOfCollectionMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "CollectionMetadataOneOfCollectionMetadata") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "CollectionMetadataOneOfCollectionMetadata") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class CollectionTypeEnum(str, Enum):
        """
        The type of resources in the resource array.
        """

        APPLICATION_VND_IBM_KMS_ALLOWED_IP_METADATA_JSON = (
            "application/vnd.ibm.kms.allowed_ip_metadata+json"
        )
        APPLICATION_VND_IBM_KMS_CRN_JSON = "application/vnd.ibm.kms.crn+json"
        APPLICATION_VND_IBM_KMS_ERROR_JSON = "application/vnd.ibm.kms.error+json"
        APPLICATION_VND_IBM_KMS_EVENT_ACKNOWLEDGE_JSON = (
            "application/vnd.ibm.kms.event_acknowledge+json"
        )
        APPLICATION_VND_IBM_KMS_IMPORT_TOKEN_JSON = (
            "application/vnd.ibm.kms.import_token+json"
        )
        APPLICATION_VND_IBM_KMS_KEY_JSON = "application/vnd.ibm.kms.key+json"
        APPLICATION_VND_IBM_KMS_KEY_ACTION_JSON = (
            "application/vnd.ibm.kms.key_action+json"
        )
        APPLICATION_VND_IBM_KMS_ALIAS_JSON = "application/vnd.ibm.kms.alias+json"
        APPLICATION_VND_IBM_KMS_KEY_RING_JSON = "application/vnd.ibm.kms.key_ring+json"
        APPLICATION_VND_IBM_KMS_POLICY_JSON = "application/vnd.ibm.kms.policy+json"
        APPLICATION_VND_IBM_KMS_REGISTRATION_INPUT_JSON = (
            "application/vnd.ibm.kms.registration_input+json"
        )
        APPLICATION_VND_IBM_KMS_REGISTRATION_JSON = (
            "application/vnd.ibm.kms.registration+json"
        )
        APPLICATION_VND_IBM_KMS_RESOURCE_CRN_JSON = (
            "application/vnd.ibm.kms.resource_crn+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_ADAPTER_JSON = (
            "application/vnd.ibm.kms.kmip_adapter+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_CLIENT_CERTIFICATE_JSON = (
            "application/vnd.ibm.kms.kmip_client_certificate+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_OBJECT_JSON = (
            "application/vnd.ibm.kms.kmip_object+json"
        )


class GetInstancePoliciesOneOfGetInstancePolicyAllowedIP(GetInstancePoliciesOneOf):
    """
    Properties that are associated with retrieving an instance level allowed IP policy.

    :param CollectionMetadataOneOf metadata:
    :param List[GetInstancePolicyAllowedIPResourcesItem] resources: A collection of
          resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadataOneOf",
        resources: List["GetInstancePolicyAllowedIPResourcesItem"],
    ) -> None:
        """
        Initialize a GetInstancePoliciesOneOfGetInstancePolicyAllowedIP object.

        :param CollectionMetadataOneOf metadata:
        :param List[GetInstancePolicyAllowedIPResourcesItem] resources: A
               collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePoliciesOneOfGetInstancePolicyAllowedIP":
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyAllowedIP object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = metadata
        else:
            raise ValueError(
                "Required property 'metadata' not present in GetInstancePoliciesOneOfGetInstancePolicyAllowedIP JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                GetInstancePolicyAllowedIPResourcesItem.from_dict(v) for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in GetInstancePoliciesOneOfGetInstancePolicyAllowedIP JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyAllowedIP object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePoliciesOneOfGetInstancePolicyAllowedIP object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "GetInstancePoliciesOneOfGetInstancePolicyAllowedIP"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "GetInstancePoliciesOneOfGetInstancePolicyAllowedIP"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork(GetInstancePoliciesOneOf):
    """
    Properties that are associated with retrieving an instance level allowed network
    policy.

    :param CollectionMetadataOneOf metadata:
    :param
          List[GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem]
          resources: A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadataOneOf",
        resources: List[
            "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem"
        ],
    ) -> None:
        """
        Initialize a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork object.

        :param CollectionMetadataOneOf metadata:
        :param
               List[GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem]
               resources: A collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork":
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = metadata
        else:
            raise ValueError(
                "Required property 'metadata' not present in GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem.from_dict(
                    v
                )
                for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete(GetInstancePoliciesOneOf):
    """
    Properties that are associated with retrieving an instance level dual authorization
    delete policy.

    :param CollectionMetadataOneOf metadata:
    :param List[GetInstancePolicyDualAuthDeleteResourcesItem] resources: A
          collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadataOneOf",
        resources: List["GetInstancePolicyDualAuthDeleteResourcesItem"],
    ) -> None:
        """
        Initialize a GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete object.

        :param CollectionMetadataOneOf metadata:
        :param List[GetInstancePolicyDualAuthDeleteResourcesItem] resources: A
               collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete":
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = metadata
        else:
            raise ValueError(
                "Required property 'metadata' not present in GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                GetInstancePolicyDualAuthDeleteResourcesItem.from_dict(v)
                for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess(
    GetInstancePoliciesOneOf
):
    """
    Properties that are associated with retrieving an instance level key create and import
    access policy.

    :param CollectionMetadataOneOf metadata:
    :param
          List[GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem]
          resources: A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadataOneOf",
        resources: List[
            "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem"
        ],
    ) -> None:
        """
        Initialize a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess object.

        :param CollectionMetadataOneOf metadata:
        :param
               List[GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem]
               resources: A collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess":
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = metadata
        else:
            raise ValueError(
                "Required property 'metadata' not present in GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem.from_dict(
                    v
                )
                for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePoliciesOneOfGetInstancePolicyMetrics(GetInstancePoliciesOneOf):
    """
    Properties that are associated with retrieving an instance level metrics policy.

    :param CollectionMetadataOneOf metadata:
    :param List[GetInstancePolicyMetricsResourcesItem] resources: A collection of
          resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadataOneOf",
        resources: List["GetInstancePolicyMetricsResourcesItem"],
    ) -> None:
        """
        Initialize a GetInstancePoliciesOneOfGetInstancePolicyMetrics object.

        :param CollectionMetadataOneOf metadata:
        :param List[GetInstancePolicyMetricsResourcesItem] resources: A collection
               of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePoliciesOneOfGetInstancePolicyMetrics":
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyMetrics object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = metadata
        else:
            raise ValueError(
                "Required property 'metadata' not present in GetInstancePoliciesOneOfGetInstancePolicyMetrics JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                GetInstancePolicyMetricsResourcesItem.from_dict(v) for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in GetInstancePoliciesOneOfGetInstancePolicyMetrics JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyMetrics object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePoliciesOneOfGetInstancePolicyMetrics object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "GetInstancePoliciesOneOfGetInstancePolicyMetrics") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "GetInstancePoliciesOneOfGetInstancePolicyMetrics") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePoliciesOneOfGetInstancePolicyRotation(GetInstancePoliciesOneOf):
    """
    Properties that are associated with retrieving an instance level rotation policy.

    :param CollectionMetadataOneOf metadata:
    :param List[GetInstancePolicyRotationResourcesItem] resources: A collection of
          resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadataOneOf",
        resources: List["GetInstancePolicyRotationResourcesItem"],
    ) -> None:
        """
        Initialize a GetInstancePoliciesOneOfGetInstancePolicyRotation object.

        :param CollectionMetadataOneOf metadata:
        :param List[GetInstancePolicyRotationResourcesItem] resources: A collection
               of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePoliciesOneOfGetInstancePolicyRotation":
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyRotation object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = metadata
        else:
            raise ValueError(
                "Required property 'metadata' not present in GetInstancePoliciesOneOfGetInstancePolicyRotation JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                GetInstancePolicyRotationResourcesItem.from_dict(v) for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in GetInstancePoliciesOneOfGetInstancePolicyRotation JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePoliciesOneOfGetInstancePolicyRotation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePoliciesOneOfGetInstancePolicyRotation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "GetInstancePoliciesOneOfGetInstancePolicyRotation"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "GetInstancePoliciesOneOfGetInstancePolicyRotation"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetInstancePoliciesOneOfGetMultipleInstancePolicies(GetInstancePoliciesOneOf):
    """
    Properties that are associated with the instance level policies.

    :param CollectionMetadataOneOf metadata:
    :param List[InstancePolicyResource] resources: A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadataOneOf",
        resources: List["InstancePolicyResource"],
    ) -> None:
        """
        Initialize a GetInstancePoliciesOneOfGetMultipleInstancePolicies object.

        :param CollectionMetadataOneOf metadata:
        :param List[InstancePolicyResource] resources: A collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "GetInstancePoliciesOneOfGetMultipleInstancePolicies":
        """Initialize a GetInstancePoliciesOneOfGetMultipleInstancePolicies object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = metadata
        else:
            raise ValueError(
                "Required property 'metadata' not present in GetInstancePoliciesOneOfGetMultipleInstancePolicies JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [InstancePolicyResource.from_dict(v) for v in resources]
        else:
            raise ValueError(
                "Required property 'resources' not present in GetInstancePoliciesOneOfGetMultipleInstancePolicies JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstancePoliciesOneOfGetMultipleInstancePolicies object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstancePoliciesOneOfGetMultipleInstancePolicies object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "GetInstancePoliciesOneOfGetMultipleInstancePolicies"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "GetInstancePoliciesOneOfGetMultipleInstancePolicies"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete(GetKeyPoliciesOneOf):
    """
    The base schema for retrieving a dual authorization key policy.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param List[GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem]
          resources: A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List["GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem"],
    ) -> None:
        """
        Initialize a GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem]
               resources: A collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete":
        """Initialize a GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem.from_dict(v)
                for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetKeyPoliciesOneOfGetKeyPolicyRotation(GetKeyPoliciesOneOf):
    """
    The base schema for retrieving a dual authorization key policy.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param List[GetKeyPolicyRotationResourcesItem] resources: A collection of
          resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List["GetKeyPolicyRotationResourcesItem"],
    ) -> None:
        """
        Initialize a GetKeyPoliciesOneOfGetKeyPolicyRotation object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[GetKeyPolicyRotationResourcesItem] resources: A collection of
               resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "GetKeyPoliciesOneOfGetKeyPolicyRotation":
        """Initialize a GetKeyPoliciesOneOfGetKeyPolicyRotation object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in GetKeyPoliciesOneOfGetKeyPolicyRotation JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                GetKeyPolicyRotationResourcesItem.from_dict(v) for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in GetKeyPoliciesOneOfGetKeyPolicyRotation JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetKeyPoliciesOneOfGetKeyPolicyRotation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetKeyPoliciesOneOfGetKeyPolicyRotation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "GetKeyPoliciesOneOfGetKeyPolicyRotation") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "GetKeyPoliciesOneOfGetKeyPolicyRotation") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetKeyPoliciesOneOfGetMultipleKeyPolicies(GetKeyPoliciesOneOf):
    """
    The base schema for retrieving all key policies.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param List[GetMultipleKeyPoliciesResource] resources: A collection of
          resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List["GetMultipleKeyPoliciesResource"],
    ) -> None:
        """
        Initialize a GetKeyPoliciesOneOfGetMultipleKeyPolicies object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[GetMultipleKeyPoliciesResource] resources: A collection of
               resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "GetKeyPoliciesOneOfGetMultipleKeyPolicies":
        """Initialize a GetKeyPoliciesOneOfGetMultipleKeyPolicies object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in GetKeyPoliciesOneOfGetMultipleKeyPolicies JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                GetMultipleKeyPoliciesResource.from_dict(v) for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in GetKeyPoliciesOneOfGetMultipleKeyPolicies JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetKeyPoliciesOneOfGetMultipleKeyPolicies object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetKeyPoliciesOneOfGetMultipleKeyPolicies object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "GetKeyPoliciesOneOfGetMultipleKeyPolicies") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "GetKeyPoliciesOneOfGetMultipleKeyPolicies") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KMIPProfileDataBodyKMIPProfileDataNative(KMIPProfileDataBody):
    """
    Properties that must be specified to profile_data when it is of native_1.0 KMIP
    adapter resource.

    :param str crk_id: An ID that identifies the Customer Root Key(CRK) to be used.
          This CRK must exist in the same kms instance as the adapter.
    """

    def __init__(
        self,
        crk_id: str,
    ) -> None:
        """
        Initialize a KMIPProfileDataBodyKMIPProfileDataNative object.

        :param str crk_id: An ID that identifies the Customer Root Key(CRK) to be
               used. This CRK must exist in the same kms instance as the adapter.
        """
        # pylint: disable=super-init-not-called
        self.crk_id = crk_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KMIPProfileDataBodyKMIPProfileDataNative":
        """Initialize a KMIPProfileDataBodyKMIPProfileDataNative object from a json dictionary."""
        args = {}
        if (crk_id := _dict.get("crk_id")) is not None:
            args["crk_id"] = crk_id
        else:
            raise ValueError(
                "Required property 'crk_id' not present in KMIPProfileDataBodyKMIPProfileDataNative JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KMIPProfileDataBodyKMIPProfileDataNative object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "crk_id") and self.crk_id is not None:
            _dict["crk_id"] = self.crk_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KMIPProfileDataBodyKMIPProfileDataNative object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KMIPProfileDataBodyKMIPProfileDataNative") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KMIPProfileDataBodyKMIPProfileDataNative") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KeyActionOneOfResponseRewrapKeyResponseBody(KeyActionOneOfResponse):
    """
    Properties that are associated with the response body of an rewrap action.

    :param str ciphertext: (optional) The wrapped data encryption key (WDEK) that
          you can export to your app or service. The ciphertext contains the DEK wrapped
          by the latest version of the key (WDEK). It is recommended to store and use this
          WDEK in future calls to Key Protect. The value is base64 encoded.
    :param WrappedKeyVersionKeyVersion key_version: (optional) The key version that
          was used to wrap the DEK. This key version is associated with the `ciphertext`
          value that was used in the request.
    :param RewrappedKeyVersionRewrappedKeyVersion rewrapped_key_version: (optional)
          The latest key version that was used to rewrap the DEK. This key version is
          associated with the `ciphertext` value that's returned in the response.
    """

    def __init__(
        self,
        *,
        ciphertext: Optional[str] = None,
        key_version: Optional["WrappedKeyVersionKeyVersion"] = None,
        rewrapped_key_version: Optional[
            "RewrappedKeyVersionRewrappedKeyVersion"
        ] = None,
    ) -> None:
        """
        Initialize a KeyActionOneOfResponseRewrapKeyResponseBody object.

        :param str ciphertext: (optional) The wrapped data encryption key (WDEK)
               that you can export to your app or service. The ciphertext contains the DEK
               wrapped by the latest version of the key (WDEK). It is recommended to store
               and use this WDEK in future calls to Key Protect. The value is base64
               encoded.
        """
        # pylint: disable=super-init-not-called
        self.ciphertext = ciphertext
        self.key_version = key_version
        self.rewrapped_key_version = rewrapped_key_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyActionOneOfResponseRewrapKeyResponseBody":
        """Initialize a KeyActionOneOfResponseRewrapKeyResponseBody object from a json dictionary."""
        args = {}
        if (ciphertext := _dict.get("ciphertext")) is not None:
            args["ciphertext"] = ciphertext
        if (key_version := _dict.get("keyVersion")) is not None:
            args["key_version"] = WrappedKeyVersionKeyVersion.from_dict(key_version)
        if (rewrapped_key_version := _dict.get("rewrappedKeyVersion")) is not None:
            args["rewrapped_key_version"] = (
                RewrappedKeyVersionRewrappedKeyVersion.from_dict(rewrapped_key_version)
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyActionOneOfResponseRewrapKeyResponseBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "ciphertext") and self.ciphertext is not None:
            _dict["ciphertext"] = self.ciphertext
        if hasattr(self, "key_version") and getattr(self, "key_version") is not None:
            if isinstance(getattr(self, "key_version"), dict):
                _dict["keyVersion"] = getattr(self, "key_version")
            else:
                _dict["keyVersion"] = getattr(self, "key_version").to_dict()
        if (
            hasattr(self, "rewrapped_key_version")
            and getattr(self, "rewrapped_key_version") is not None
        ):
            if isinstance(getattr(self, "rewrapped_key_version"), dict):
                _dict["rewrappedKeyVersion"] = getattr(self, "rewrapped_key_version")
            else:
                _dict["rewrappedKeyVersion"] = getattr(
                    self, "rewrapped_key_version"
                ).to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyActionOneOfResponseRewrapKeyResponseBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyActionOneOfResponseRewrapKeyResponseBody") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyActionOneOfResponseRewrapKeyResponseBody") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KeyActionOneOfResponseUnwrapKeyResponseBody(KeyActionOneOfResponse):
    """
    Properties that are associated with the response body of an unwrap action.

    :param str plaintext: (optional) The data encryption key (DEK) used in wrap
          actions when the query parameter is set to `wrap`. The system returns a base64
          encoded plaintext in the response entity-body when you perform an `unwrap`
          action on a key. To wrap an existing DEK, provide a base64 encoded plaintext
          during a `wrap` action. To generate a new DEK, omit the `plaintext` property.
          Key Protect generates a random plaintext (32 bytes) that is rooted in an HSM and
          then wraps that value.
          **Note:** When you unwrap a wrapped data encryption key (WDEK) by using a
          rotated root key, the service returns a new ciphertext in the response
          entity-body. Each ciphertext remains available for `unwrap` actions. If you
          unwrap a DEK with a previous ciphertext, the service also returns the latest
          ciphertext in the response. Use the latest ciphertext for future unwrap
          operations.
    :param str ciphertext: (optional) The wrapped data encryption key (WDEK) that
          you can export to your app or service. The ciphertext contains the DEK wrapped
          by the latest version of the key (WDEK). It is recommended to store and use this
          WDEK in future calls to Key Protect. The value is base64 encoded.
    :param WrappedKeyVersionKeyVersion key_version: (optional) The key version that
          was used to wrap the DEK. This key version is associated with the `ciphertext`
          value that was used in the request.
    :param RewrappedKeyVersionRewrappedKeyVersion rewrapped_key_version: (optional)
          The latest key version that was used to rewrap the DEK. This key version is
          associated with the `ciphertext` value that's returned in the response.
    """

    def __init__(
        self,
        *,
        plaintext: Optional[str] = None,
        ciphertext: Optional[str] = None,
        key_version: Optional["WrappedKeyVersionKeyVersion"] = None,
        rewrapped_key_version: Optional[
            "RewrappedKeyVersionRewrappedKeyVersion"
        ] = None,
    ) -> None:
        """
        Initialize a KeyActionOneOfResponseUnwrapKeyResponseBody object.

        :param str plaintext: (optional) The data encryption key (DEK) used in wrap
               actions when the query parameter is set to `wrap`. The system returns a
               base64 encoded plaintext in the response entity-body when you perform an
               `unwrap` action on a key. To wrap an existing DEK, provide a base64 encoded
               plaintext during a `wrap` action. To generate a new DEK, omit the
               `plaintext` property. Key Protect generates a random plaintext (32 bytes)
               that is rooted in an HSM and then wraps that value.
               **Note:** When you unwrap a wrapped data encryption key (WDEK) by using a
               rotated root key, the service returns a new ciphertext in the response
               entity-body. Each ciphertext remains available for `unwrap` actions. If you
               unwrap a DEK with a previous ciphertext, the service also returns the
               latest ciphertext in the response. Use the latest ciphertext for future
               unwrap operations.
        :param str ciphertext: (optional) The wrapped data encryption key (WDEK)
               that you can export to your app or service. The ciphertext contains the DEK
               wrapped by the latest version of the key (WDEK). It is recommended to store
               and use this WDEK in future calls to Key Protect. The value is base64
               encoded.
        """
        # pylint: disable=super-init-not-called
        self.plaintext = plaintext
        self.ciphertext = ciphertext
        self.key_version = key_version
        self.rewrapped_key_version = rewrapped_key_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyActionOneOfResponseUnwrapKeyResponseBody":
        """Initialize a KeyActionOneOfResponseUnwrapKeyResponseBody object from a json dictionary."""
        args = {}
        if (plaintext := _dict.get("plaintext")) is not None:
            args["plaintext"] = plaintext
        if (ciphertext := _dict.get("ciphertext")) is not None:
            args["ciphertext"] = ciphertext
        if (key_version := _dict.get("keyVersion")) is not None:
            args["key_version"] = WrappedKeyVersionKeyVersion.from_dict(key_version)
        if (rewrapped_key_version := _dict.get("rewrappedKeyVersion")) is not None:
            args["rewrapped_key_version"] = (
                RewrappedKeyVersionRewrappedKeyVersion.from_dict(rewrapped_key_version)
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyActionOneOfResponseUnwrapKeyResponseBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "plaintext") and self.plaintext is not None:
            _dict["plaintext"] = self.plaintext
        if hasattr(self, "ciphertext") and self.ciphertext is not None:
            _dict["ciphertext"] = self.ciphertext
        if hasattr(self, "key_version") and getattr(self, "key_version") is not None:
            if isinstance(getattr(self, "key_version"), dict):
                _dict["keyVersion"] = getattr(self, "key_version")
            else:
                _dict["keyVersion"] = getattr(self, "key_version").to_dict()
        if (
            hasattr(self, "rewrapped_key_version")
            and getattr(self, "rewrapped_key_version") is not None
        ):
            if isinstance(getattr(self, "rewrapped_key_version"), dict):
                _dict["rewrappedKeyVersion"] = getattr(self, "rewrapped_key_version")
            else:
                _dict["rewrappedKeyVersion"] = getattr(
                    self, "rewrapped_key_version"
                ).to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyActionOneOfResponseUnwrapKeyResponseBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyActionOneOfResponseUnwrapKeyResponseBody") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyActionOneOfResponseUnwrapKeyResponseBody") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class KeyActionOneOfResponseWrapKeyResponseBody(KeyActionOneOfResponse):
    """
    Properties that are associated with the response body of a wrap action.

    :param str plaintext: (optional) The data encryption key (DEK) used in wrap
          actions when the query parameter is set to `wrap`. The system returns a base64
          encoded plaintext in the response entity-body when you perform an `unwrap`
          action on a key. To wrap an existing DEK, provide a base64 encoded plaintext
          during a `wrap` action. To generate a new DEK, omit the `plaintext` property.
          Key Protect generates a random plaintext (32 bytes) that is rooted in an HSM and
          then wraps that value.
          **Note:** When you unwrap a wrapped data encryption key (WDEK) by using a
          rotated root key, the service returns a new ciphertext in the response
          entity-body. Each ciphertext remains available for `unwrap` actions. If you
          unwrap a DEK with a previous ciphertext, the service also returns the latest
          ciphertext in the response. Use the latest ciphertext for future unwrap
          operations.
    :param str ciphertext: (optional) The wrapped data encryption key (WDEK) that
          you can export to your app or service. The ciphertext contains the DEK wrapped
          by the latest version of the key (WDEK). It is recommended to store and use this
          WDEK in future calls to Key Protect. The value is base64 encoded.
    :param WrappedKeyVersionKeyVersion key_version: (optional) The key version that
          was used to wrap the DEK. This key version is associated with the `ciphertext`
          value that was used in the request.
    """

    def __init__(
        self,
        *,
        plaintext: Optional[str] = None,
        ciphertext: Optional[str] = None,
        key_version: Optional["WrappedKeyVersionKeyVersion"] = None,
    ) -> None:
        """
        Initialize a KeyActionOneOfResponseWrapKeyResponseBody object.

        :param str plaintext: (optional) The data encryption key (DEK) used in wrap
               actions when the query parameter is set to `wrap`. The system returns a
               base64 encoded plaintext in the response entity-body when you perform an
               `unwrap` action on a key. To wrap an existing DEK, provide a base64 encoded
               plaintext during a `wrap` action. To generate a new DEK, omit the
               `plaintext` property. Key Protect generates a random plaintext (32 bytes)
               that is rooted in an HSM and then wraps that value.
               **Note:** When you unwrap a wrapped data encryption key (WDEK) by using a
               rotated root key, the service returns a new ciphertext in the response
               entity-body. Each ciphertext remains available for `unwrap` actions. If you
               unwrap a DEK with a previous ciphertext, the service also returns the
               latest ciphertext in the response. Use the latest ciphertext for future
               unwrap operations.
        :param str ciphertext: (optional) The wrapped data encryption key (WDEK)
               that you can export to your app or service. The ciphertext contains the DEK
               wrapped by the latest version of the key (WDEK). It is recommended to store
               and use this WDEK in future calls to Key Protect. The value is base64
               encoded.
        """
        # pylint: disable=super-init-not-called
        self.plaintext = plaintext
        self.ciphertext = ciphertext
        self.key_version = key_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> "KeyActionOneOfResponseWrapKeyResponseBody":
        """Initialize a KeyActionOneOfResponseWrapKeyResponseBody object from a json dictionary."""
        args = {}
        if (plaintext := _dict.get("plaintext")) is not None:
            args["plaintext"] = plaintext
        if (ciphertext := _dict.get("ciphertext")) is not None:
            args["ciphertext"] = ciphertext
        if (key_version := _dict.get("keyVersion")) is not None:
            args["key_version"] = WrappedKeyVersionKeyVersion.from_dict(key_version)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KeyActionOneOfResponseWrapKeyResponseBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "plaintext") and self.plaintext is not None:
            _dict["plaintext"] = self.plaintext
        if hasattr(self, "ciphertext") and self.ciphertext is not None:
            _dict["ciphertext"] = self.ciphertext
        if hasattr(self, "key_version") and getattr(self, "key_version") is not None:
            if isinstance(getattr(self, "key_version"), dict):
                _dict["keyVersion"] = getattr(self, "key_version")
            else:
                _dict["keyVersion"] = getattr(self, "key_version").to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KeyActionOneOfResponseWrapKeyResponseBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "KeyActionOneOfResponseWrapKeyResponseBody") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "KeyActionOneOfResponseWrapKeyResponseBody") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListCollectionMetadataCollectionMetadata(ListCollectionMetadata):
    """
    The metadata that describes the resource array.

    :param str collection_type: The type of resources in the resource array.
    :param int collection_total: The number of elements in the resource array.
    """

    def __init__(
        self,
        collection_type: str,
        collection_total: int,
    ) -> None:
        """
        Initialize a ListCollectionMetadataCollectionMetadata object.

        :param str collection_type: The type of resources in the resource array.
        :param int collection_total: The number of elements in the resource array.
        """
        # pylint: disable=super-init-not-called
        self.collection_type = collection_type
        self.collection_total = collection_total

    @classmethod
    def from_dict(cls, _dict: Dict) -> "ListCollectionMetadataCollectionMetadata":
        """Initialize a ListCollectionMetadataCollectionMetadata object from a json dictionary."""
        args = {}
        if (collection_type := _dict.get("collectionType")) is not None:
            args["collection_type"] = collection_type
        else:
            raise ValueError(
                "Required property 'collectionType' not present in ListCollectionMetadataCollectionMetadata JSON"
            )
        if (collection_total := _dict.get("collectionTotal")) is not None:
            args["collection_total"] = collection_total
        else:
            raise ValueError(
                "Required property 'collectionTotal' not present in ListCollectionMetadataCollectionMetadata JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListCollectionMetadataCollectionMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "collection_type") and self.collection_type is not None:
            _dict["collectionType"] = self.collection_type
        if hasattr(self, "collection_total") and self.collection_total is not None:
            _dict["collectionTotal"] = self.collection_total
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListCollectionMetadataCollectionMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "ListCollectionMetadataCollectionMetadata") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "ListCollectionMetadataCollectionMetadata") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class CollectionTypeEnum(str, Enum):
        """
        The type of resources in the resource array.
        """

        APPLICATION_VND_IBM_KMS_ALLOWED_IP_METADATA_JSON = (
            "application/vnd.ibm.kms.allowed_ip_metadata+json"
        )
        APPLICATION_VND_IBM_KMS_CRN_JSON = "application/vnd.ibm.kms.crn+json"
        APPLICATION_VND_IBM_KMS_ERROR_JSON = "application/vnd.ibm.kms.error+json"
        APPLICATION_VND_IBM_KMS_EVENT_ACKNOWLEDGE_JSON = (
            "application/vnd.ibm.kms.event_acknowledge+json"
        )
        APPLICATION_VND_IBM_KMS_IMPORT_TOKEN_JSON = (
            "application/vnd.ibm.kms.import_token+json"
        )
        APPLICATION_VND_IBM_KMS_KEY_JSON = "application/vnd.ibm.kms.key+json"
        APPLICATION_VND_IBM_KMS_KEY_ACTION_JSON = (
            "application/vnd.ibm.kms.key_action+json"
        )
        APPLICATION_VND_IBM_KMS_ALIAS_JSON = "application/vnd.ibm.kms.alias+json"
        APPLICATION_VND_IBM_KMS_KEY_RING_JSON = "application/vnd.ibm.kms.key_ring+json"
        APPLICATION_VND_IBM_KMS_POLICY_JSON = "application/vnd.ibm.kms.policy+json"
        APPLICATION_VND_IBM_KMS_REGISTRATION_INPUT_JSON = (
            "application/vnd.ibm.kms.registration_input+json"
        )
        APPLICATION_VND_IBM_KMS_REGISTRATION_JSON = (
            "application/vnd.ibm.kms.registration+json"
        )
        APPLICATION_VND_IBM_KMS_RESOURCE_CRN_JSON = (
            "application/vnd.ibm.kms.resource_crn+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_ADAPTER_JSON = (
            "application/vnd.ibm.kms.kmip_adapter+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_CLIENT_CERTIFICATE_JSON = (
            "application/vnd.ibm.kms.kmip_client_certificate+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_OBJECT_JSON = (
            "application/vnd.ibm.kms.kmip_object+json"
        )


class ListCollectionMetadataCollectionMetadataWithTotalCount(ListCollectionMetadata):
    """
    The metadata that describes the resource array.

    :param str collection_type: The type of resources in the resource array.
    :param int collection_total: The number of elements in the resource array.
    :param int total_count: (optional) The total number of elements that match the
          request, disregarding limit and offset.
    """

    def __init__(
        self,
        collection_type: str,
        collection_total: int,
        *,
        total_count: Optional[int] = None,
    ) -> None:
        """
        Initialize a ListCollectionMetadataCollectionMetadataWithTotalCount object.

        :param str collection_type: The type of resources in the resource array.
        :param int collection_total: The number of elements in the resource array.
        :param int total_count: (optional) The total number of elements that match
               the request, disregarding limit and offset.
        """
        # pylint: disable=super-init-not-called
        self.collection_type = collection_type
        self.collection_total = collection_total
        self.total_count = total_count

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "ListCollectionMetadataCollectionMetadataWithTotalCount":
        """Initialize a ListCollectionMetadataCollectionMetadataWithTotalCount object from a json dictionary."""
        args = {}
        if (collection_type := _dict.get("collectionType")) is not None:
            args["collection_type"] = collection_type
        else:
            raise ValueError(
                "Required property 'collectionType' not present in ListCollectionMetadataCollectionMetadataWithTotalCount JSON"
            )
        if (collection_total := _dict.get("collectionTotal")) is not None:
            args["collection_total"] = collection_total
        else:
            raise ValueError(
                "Required property 'collectionTotal' not present in ListCollectionMetadataCollectionMetadataWithTotalCount JSON"
            )
        if (total_count := _dict.get("totalCount")) is not None:
            args["total_count"] = total_count
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListCollectionMetadataCollectionMetadataWithTotalCount object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "collection_type") and self.collection_type is not None:
            _dict["collectionType"] = self.collection_type
        if hasattr(self, "collection_total") and self.collection_total is not None:
            _dict["collectionTotal"] = self.collection_total
        if hasattr(self, "total_count") and self.total_count is not None:
            _dict["totalCount"] = self.total_count
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListCollectionMetadataCollectionMetadataWithTotalCount object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "ListCollectionMetadataCollectionMetadataWithTotalCount"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "ListCollectionMetadataCollectionMetadataWithTotalCount"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class CollectionTypeEnum(str, Enum):
        """
        The type of resources in the resource array.
        """

        APPLICATION_VND_IBM_KMS_ALLOWED_IP_METADATA_JSON = (
            "application/vnd.ibm.kms.allowed_ip_metadata+json"
        )
        APPLICATION_VND_IBM_KMS_CRN_JSON = "application/vnd.ibm.kms.crn+json"
        APPLICATION_VND_IBM_KMS_ERROR_JSON = "application/vnd.ibm.kms.error+json"
        APPLICATION_VND_IBM_KMS_EVENT_ACKNOWLEDGE_JSON = (
            "application/vnd.ibm.kms.event_acknowledge+json"
        )
        APPLICATION_VND_IBM_KMS_IMPORT_TOKEN_JSON = (
            "application/vnd.ibm.kms.import_token+json"
        )
        APPLICATION_VND_IBM_KMS_KEY_JSON = "application/vnd.ibm.kms.key+json"
        APPLICATION_VND_IBM_KMS_KEY_ACTION_JSON = (
            "application/vnd.ibm.kms.key_action+json"
        )
        APPLICATION_VND_IBM_KMS_ALIAS_JSON = "application/vnd.ibm.kms.alias+json"
        APPLICATION_VND_IBM_KMS_KEY_RING_JSON = "application/vnd.ibm.kms.key_ring+json"
        APPLICATION_VND_IBM_KMS_POLICY_JSON = "application/vnd.ibm.kms.policy+json"
        APPLICATION_VND_IBM_KMS_REGISTRATION_INPUT_JSON = (
            "application/vnd.ibm.kms.registration_input+json"
        )
        APPLICATION_VND_IBM_KMS_REGISTRATION_JSON = (
            "application/vnd.ibm.kms.registration+json"
        )
        APPLICATION_VND_IBM_KMS_RESOURCE_CRN_JSON = (
            "application/vnd.ibm.kms.resource_crn+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_ADAPTER_JSON = (
            "application/vnd.ibm.kms.kmip_adapter+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_CLIENT_CERTIFICATE_JSON = (
            "application/vnd.ibm.kms.kmip_client_certificate+json"
        )
        APPLICATION_VND_IBM_KMS_KMIP_OBJECT_JSON = (
            "application/vnd.ibm.kms.kmip_object+json"
        )


class SetInstancePoliciesOneOfSetInstancePolicyAllowedIP(SetInstancePoliciesOneOf):
    """
    Properties that are associated with setting an instance level allowed IP policy.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param List[SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem]
          resources: A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List[
            "SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem"
        ],
    ) -> None:
        """
        Initialize a SetInstancePoliciesOneOfSetInstancePolicyAllowedIP object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param
               List[SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem]
               resources: A collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "SetInstancePoliciesOneOfSetInstancePolicyAllowedIP":
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyAllowedIP object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in SetInstancePoliciesOneOfSetInstancePolicyAllowedIP JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem.from_dict(
                    v
                )
                for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in SetInstancePoliciesOneOfSetInstancePolicyAllowedIP JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyAllowedIP object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetInstancePoliciesOneOfSetInstancePolicyAllowedIP object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyAllowedIP"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyAllowedIP"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork(SetInstancePoliciesOneOf):
    """
    Properties that are associated with setting an instance level allowed network policy.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param
          List[SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem]
          resources: A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List[
            "SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem"
        ],
    ) -> None:
        """
        Initialize a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param
               List[SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem]
               resources: A collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork":
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem.from_dict(
                    v
                )
                for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete(SetInstancePoliciesOneOf):
    """
    Properties that are associated with setting a dual authorization delete instance
    policy.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param List[SetInstancePolicyDualAuthDeleteResourcesItem] resources: A
          collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List["SetInstancePolicyDualAuthDeleteResourcesItem"],
    ) -> None:
        """
        Initialize a SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SetInstancePolicyDualAuthDeleteResourcesItem] resources: A
               collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete":
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                SetInstancePolicyDualAuthDeleteResourcesItem.from_dict(v)
                for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess(
    SetInstancePoliciesOneOf
):
    """
    Properties that are associated with setting an instance level key create and import
    access policy.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param
          List[SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem]
          resources: A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List[
            "SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem"
        ],
    ) -> None:
        """
        Initialize a SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param
               List[SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem]
               resources: A collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess":
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem.from_dict(
                    v
                )
                for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SetInstancePoliciesOneOfSetInstancePolicyMetrics(SetInstancePoliciesOneOf):
    """
    Properties that are associated with setting a metrics instance policy.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param List[SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem]
          resources: A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List[
            "SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem"
        ],
    ) -> None:
        """
        Initialize a SetInstancePoliciesOneOfSetInstancePolicyMetrics object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem]
               resources: A collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "SetInstancePoliciesOneOfSetInstancePolicyMetrics":
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyMetrics object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in SetInstancePoliciesOneOfSetInstancePolicyMetrics JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem.from_dict(
                    v
                )
                for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in SetInstancePoliciesOneOfSetInstancePolicyMetrics JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyMetrics object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetInstancePoliciesOneOfSetInstancePolicyMetrics object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "SetInstancePoliciesOneOfSetInstancePolicyMetrics") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "SetInstancePoliciesOneOfSetInstancePolicyMetrics") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SetInstancePoliciesOneOfSetInstancePolicyRotation(SetInstancePoliciesOneOf):
    """
    Properties that are associated with setting an instance level rotation policy.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param List[SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem]
          resources: A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List[
            "SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem"
        ],
    ) -> None:
        """
        Initialize a SetInstancePoliciesOneOfSetInstancePolicyRotation object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem]
               resources: A collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "SetInstancePoliciesOneOfSetInstancePolicyRotation":
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyRotation object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in SetInstancePoliciesOneOfSetInstancePolicyRotation JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem.from_dict(
                    v
                )
                for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in SetInstancePoliciesOneOfSetInstancePolicyRotation JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetInstancePoliciesOneOfSetInstancePolicyRotation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetInstancePoliciesOneOfSetInstancePolicyRotation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyRotation"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "SetInstancePoliciesOneOfSetInstancePolicyRotation"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SetInstancePoliciesOneOfSetMultipleInstancePolicies(SetInstancePoliciesOneOf):
    """
    Properties that are associated with setting any type of instance level policy.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param List[SetMultipleInstancePoliciesResourcesItem] resources: A collection of
          resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List["SetMultipleInstancePoliciesResourcesItem"],
    ) -> None:
        """
        Initialize a SetInstancePoliciesOneOfSetMultipleInstancePolicies object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SetMultipleInstancePoliciesResourcesItem] resources: A
               collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(
        cls, _dict: Dict
    ) -> "SetInstancePoliciesOneOfSetMultipleInstancePolicies":
        """Initialize a SetInstancePoliciesOneOfSetMultipleInstancePolicies object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in SetInstancePoliciesOneOfSetMultipleInstancePolicies JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                SetMultipleInstancePoliciesResourcesItem.from_dict(v) for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in SetInstancePoliciesOneOfSetMultipleInstancePolicies JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetInstancePoliciesOneOfSetMultipleInstancePolicies object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetInstancePoliciesOneOfSetMultipleInstancePolicies object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(
        self, other: "SetInstancePoliciesOneOfSetMultipleInstancePolicies"
    ) -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(
        self, other: "SetInstancePoliciesOneOfSetMultipleInstancePolicies"
    ) -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete(SetKeyPoliciesOneOf):
    """
    Base schema for request of create/update of key level dual authorization delete
    policy.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param List[KeyPolicyDualAuthDelete] resources: A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List["KeyPolicyDualAuthDelete"],
    ) -> None:
        """
        Initialize a SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[KeyPolicyDualAuthDelete] resources: A collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete":
        """Initialize a SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                KeyPolicyDualAuthDelete.from_dict(v) for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SetKeyPoliciesOneOfSetKeyPolicyRotation(SetKeyPoliciesOneOf):
    """
    Base schema for request of create/update of key level rotation policy.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param List[KeyPolicyRotation] resources: A collection of resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List["KeyPolicyRotation"],
    ) -> None:
        """
        Initialize a SetKeyPoliciesOneOfSetKeyPolicyRotation object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[KeyPolicyRotation] resources: A collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "SetKeyPoliciesOneOfSetKeyPolicyRotation":
        """Initialize a SetKeyPoliciesOneOfSetKeyPolicyRotation object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in SetKeyPoliciesOneOfSetKeyPolicyRotation JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [KeyPolicyRotation.from_dict(v) for v in resources]
        else:
            raise ValueError(
                "Required property 'resources' not present in SetKeyPoliciesOneOfSetKeyPolicyRotation JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetKeyPoliciesOneOfSetKeyPolicyRotation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetKeyPoliciesOneOfSetKeyPolicyRotation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "SetKeyPoliciesOneOfSetKeyPolicyRotation") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "SetKeyPoliciesOneOfSetKeyPolicyRotation") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SetKeyPoliciesOneOfSetMultipleKeyPolicies(SetKeyPoliciesOneOf):
    """
    Properties that are associated with key.

    :param CollectionMetadata metadata: The metadata that describes the resource
          array.
    :param List[SetMultipleKeyPoliciesResource] resources: A collection of
          resources.
    """

    def __init__(
        self,
        metadata: "CollectionMetadata",
        resources: List["SetMultipleKeyPoliciesResource"],
    ) -> None:
        """
        Initialize a SetKeyPoliciesOneOfSetMultipleKeyPolicies object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SetMultipleKeyPoliciesResource] resources: A collection of
               resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> "SetKeyPoliciesOneOfSetMultipleKeyPolicies":
        """Initialize a SetKeyPoliciesOneOfSetMultipleKeyPolicies object from a json dictionary."""
        args = {}
        if (metadata := _dict.get("metadata")) is not None:
            args["metadata"] = CollectionMetadata.from_dict(metadata)
        else:
            raise ValueError(
                "Required property 'metadata' not present in SetKeyPoliciesOneOfSetMultipleKeyPolicies JSON"
            )
        if (resources := _dict.get("resources")) is not None:
            args["resources"] = [
                SetMultipleKeyPoliciesResource.from_dict(v) for v in resources
            ]
        else:
            raise ValueError(
                "Required property 'resources' not present in SetKeyPoliciesOneOfSetMultipleKeyPolicies JSON"
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetKeyPoliciesOneOfSetMultipleKeyPolicies object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, "metadata") and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict["metadata"] = self.metadata
            else:
                _dict["metadata"] = self.metadata.to_dict()
        if hasattr(self, "resources") and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict["resources"] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetKeyPoliciesOneOfSetMultipleKeyPolicies object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: "SetKeyPoliciesOneOfSetMultipleKeyPolicies") -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: "SetKeyPoliciesOneOfSetMultipleKeyPolicies") -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other
