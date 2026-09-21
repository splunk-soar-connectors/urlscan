# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.actions.make_request import run_make_request
from src.params import UrlscanMakeRequestParams


@pytest.mark.parametrize("verify_ssl", [True, False])
def test_make_request_honors_secure_default_and_explicit_opt_out(mocker, verify_ssl):
    response = MagicMock(status_code=200, text="{}")
    http_client = MagicMock()
    http_client.__enter__.return_value.request.return_value = response
    client_factory = mocker.patch(
        "src.actions.make_request.httpx.Client", return_value=http_client
    )
    params = UrlscanMakeRequestParams(
        http_method="GET",
        endpoint="api/v1/search/",
        **({} if verify_ssl else {"verify_ssl": False}),
    )

    run_make_request(
        params,
        SimpleNamespace(api_key=None, timeout=None, verify_server_cert=True),
    )

    client_factory.assert_called_once_with(verify=verify_ssl)
