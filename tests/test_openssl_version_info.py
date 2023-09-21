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
import os
import ssl

from pskcontext import PSKContext


def _expected_openssl_version_info():
    if os.getenv("EXPECTED_OPENSSL_VERSION"):
        # Currently only OpenSSL 3.0.8
        return 3, 0, 0, 8, 0
    return ssl.OPENSSL_VERSION_INFO


def test_openssl_version_info():
    context = PSKContext()

    version_info = context.openssl_version_info
    assert _expected_openssl_version_info() == version_info
