"""Common utilities for the IBM Key Protect SDK."""
import platform
import uuid
from .version import __version__

HEADER_NAME_X_REQUEST_ID = 'X-Request-Id'
HEADER_NAME_USER_AGENT = 'User-Agent'
HEADER_NAME_X_CORRELATION_ID = 'X-Correlation-ID'
SDK_NAME = 'keyprotect-python-sdk'


def get_system_info():
    """
    Get information about the system to be inserted into the User-Agent header.
    """
    return 'lang={0}; arch={1}; os={2}; python.version={3}'.format(
        'python', platform.machine(), platform.system(), platform.python_version()  # Architecture  # OS
    )  # Python version


def get_sdk_headers(service_name, service_version, operation_id, correlation_id=None):
    # pylint: disable=unused-argument
    """
    Get the request headers to be sent in requests by the SDK.

    """
    headers = {}
    headers[HEADER_NAME_X_REQUEST_ID] = get_x_request_id()
    headers[HEADER_NAME_X_CORRELATION_ID] = get_x_correlation_id(correlation_id)
    return headers

def get_x_request_id():
    """
    Get the value to be sent in the X-Request-Id header.
    """
    return str(uuid.uuid4())

def get_x_correlation_id(correlation_id=None) -> str:
    """
    Get the value of the header "X-Correlation-ID" if set. If it is not, generate one.
    """
    if correlation_id:
        return correlation_id
    return str(uuid.uuid4())

def get_user_agent():
    """
    Get the value to be sent in the User-Agent header.
    """
    return USER_AGENT

USER_AGENT = '{0}/{1} ({2})'.format(SDK_NAME, __version__, get_system_info())
