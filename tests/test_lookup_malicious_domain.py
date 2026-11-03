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
from pydantic import ValidationError
from soar_sdk.exceptions import ActionFailure

from src.actions.lookup import run_lookup_malicious_domain
from src.client import UrlscanResponse
from src.params import LookupMaliciousDomainParams

API_KEY = "test-api-key"  # pragma: allowlist secret


def _asset(api_key=API_KEY):
    return SimpleNamespace(api_key=api_key, timeout=None, verify_server_cert=True)


def test_lookup_malicious_domain_returns_count_and_summary(mocker):
    request = mocker.patch(
        "src.actions.lookup.UrlscanClient.request",
        return_value=UrlscanResponse(
            True,
            {
                "observable": "example.com",
                "type": "domain",
                "count": 2,
                "firstSeen": "2019-08-24T14:15:22Z",
                "lastSeen": "2020-01-01T00:00:00Z",
            },
        ),
    )
    soar = MagicMock()

    output = run_lookup_malicious_domain(
        LookupMaliciousDomainParams(domain=" example.com "), soar, _asset()
    )

    request.assert_called_once_with(
        "/api/v1/malicious/domain/example.com", headers={"API-Key": API_KEY}
    )
    assert output.count == 2
    assert output.firstSeen == "2019-08-24T14:15:22Z"
    summary = soar.set_summary.call_args.args[0]
    assert summary.count == 2
    assert summary.first_seen == "2019-08-24T14:15:22Z"
    assert summary.last_seen == "2020-01-01T00:00:00Z"
    soar.set_message.assert_called_once_with(
        "Domain has been seen in 2 malicious scan results"
    )


def test_lookup_malicious_domain_allows_zero_count_with_null_timestamps(mocker):
    mocker.patch(
        "src.actions.lookup.UrlscanClient.request",
        return_value=UrlscanResponse(
            True,
            {
                "observable": "example.com",
                "type": "domain",
                "count": 0,
                "firstSeen": None,
                "lastSeen": None,
            },
        ),
    )
    soar = MagicMock()

    output = run_lookup_malicious_domain(
        LookupMaliciousDomainParams(domain="example.com"), soar, _asset()
    )

    assert output.count == 0
    summary = soar.set_summary.call_args.args[0]
    assert summary.first_seen is None
    assert summary.last_seen is None


def test_lookup_malicious_domain_requires_api_key(mocker):
    request = mocker.patch("src.actions.lookup.UrlscanClient.request")

    with pytest.raises(ActionFailure, match="Pro API key"):
        run_lookup_malicious_domain(
            LookupMaliciousDomainParams(domain="example.com"),
            MagicMock(),
            _asset(api_key=None),
        )

    request.assert_not_called()


@pytest.mark.parametrize("count", [None, -1, True, "2"])
def test_lookup_malicious_domain_rejects_invalid_count(mocker, count):
    mocker.patch(
        "src.actions.lookup.UrlscanClient.request",
        return_value=UrlscanResponse(
            True, {"observable": "example.com", "count": count}
        ),
    )

    with pytest.raises(ActionFailure, match="valid count"):
        run_lookup_malicious_domain(
            LookupMaliciousDomainParams(domain="example.com"), MagicMock(), _asset()
        )


def test_lookup_malicious_domain_raises_server_error(mocker):
    mocker.patch(
        "src.actions.lookup.UrlscanClient.request",
        return_value=UrlscanResponse(False, {"message": "Forbidden"}, "Status 403"),
    )

    with pytest.raises(ActionFailure, match="Status 403"):
        run_lookup_malicious_domain(
            LookupMaliciousDomainParams(domain="example.com"), MagicMock(), _asset()
        )


@pytest.mark.parametrize("domain", ["", "https://example.com", "8.8.8.8"])
def test_lookup_malicious_domain_params_reject_invalid_domain(domain):
    with pytest.raises(ValidationError):
        LookupMaliciousDomainParams(domain=domain)
