#  Copyright (c) 2023. Martin Storgaard Dieu <martin@storgaarddieu.com>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import ssl
import typing
from ssl import _ASN1Object

import _pskcontext

Purpose = ssl.Purpose
ssl.create_default_context()


class PSKContext(ssl.SSLContext):
    @property
    def openssl_version_info(self) -> typing.Tuple[int, int, int, int, int]:
        """Version information about the OpenSSL library used.

        The format is identical to Python's ssl.OPENSSL_VERSION_INFO.

        The version might be different from the version it was compiled against.

        :return: A tuple with (major, minor, fix, patch, status) version information.
        """
        library_version: int = _pskcontext.openssl_version_number()

        status = library_version & 0xF
        library_version >>= 4
        patch = library_version & 0xFF
        library_version >>= 8
        fix = library_version & 0xFF
        library_version >>= 8
        minor = library_version & 0xFF
        library_version >>= 8
        major = library_version & 0xFF

        return major, minor, fix, patch, status


def create_default_psk_context(
    purpose: Purpose = Purpose.CLIENT_AUTH, *, psk: bytes
) -> PSKContext:
    if not isinstance(purpose, _ASN1Object):
        raise TypeError(purpose)
    psk_context = PSKContext(
        ssl.PROTOCOL_TLS_CLIENT
        if purpose == Purpose.CLIENT_AUTH
        else ssl.PROTOCOL_TLS_SERVER
    )

    return psk_context
