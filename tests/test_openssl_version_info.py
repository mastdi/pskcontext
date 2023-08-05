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
from os import getenv
from ssl import OPENSSL_VERSION_INFO

from pskcontext import PSKContext


def _expected_openssl_version_info():
    expected_openssl_version = getenv("PSKCONTEXT_EXPECTED_OPENSSL_VERSION", None)
    if expected_openssl_version is None:
        return OPENSSL_VERSION_INFO
    assert "3.0.8", "Currently only OpenSSL 3.0.8 or built-in is supported"
    return 3, 0, 0, 8, 0


def test_openssl_version_info():
    context = PSKContext()

    version_info = context.openssl_version_info
    assert _expected_openssl_version_info() == version_info
