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
import io
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from soar_sdk.exceptions import ActionFailure, SoarAPIError

from src.actions.screenshot import run_get_screenshot
from src.client import UrlscanClient
from src.constants import URLSCAN_DEFAULT_MAX_SCREENSHOT_SIZE_MB


class StreamResponse:
    def __init__(self, chunks: list[bytes], headers: dict[str, str] | None = None):
        self.status_code = 200
        self.headers = headers or {"Content-Type": "image/png"}
        self.url = httpx.URL("https://urlscan.io/screenshots/example.png")
        self._chunks = chunks
        self.iterated = False

    def iter_bytes(self, _chunk_size: int):
        self.iterated = True
        yield from self._chunks


class StreamContext:
    def __init__(self, response: StreamResponse):
        self.response = response

    def __enter__(self):
        return self.response

    def __exit__(self, *_args):
        return False


class HttpClient:
    def __init__(self, response: StreamResponse, **_kwargs):
        self.response = response
        self.stream_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def stream(self, *_args, **_kwargs):
        self.stream_calls += 1
        return StreamContext(self.response)


def test_download_screenshot_rejects_declared_oversize_without_reading_body(mocker):
    response = StreamResponse(
        [b"body-must-not-be-read"],
        {"Content-Type": "image/png", "Content-Length": "6"},
    )
    client = HttpClient(response)
    mocker.patch("src.client.httpx.Client", return_value=client)

    with pytest.raises(ActionFailure, match="maximum download size"):
        UrlscanClient("", 30, True).download_screenshot("/screenshot", io.BytesIO(), 5)

    assert client.stream_calls == 1
    assert response.iterated is False


def test_download_screenshot_stops_at_cumulative_limit(mocker):
    response = StreamResponse([b"abc", b"def"])
    mocker.patch("src.client.httpx.Client", return_value=HttpClient(response))
    destination = io.BytesIO()

    with pytest.raises(ActionFailure, match="maximum download size"):
        UrlscanClient("", 30, True).download_screenshot("/screenshot", destination, 5)

    assert destination.getvalue() == b"abc"


class Vault:
    def __init__(self, temporary_directory: Path, *, fail_add: bool = False):
        self.temporary_directory = temporary_directory
        self.fail_add = fail_add
        self.added_file: Path | None = None

    def get_vault_tmp_dir(self):
        return str(self.temporary_directory)

    def add_attachment(self, *, file_location, **_kwargs):
        self.added_file = Path(file_location)
        assert self.added_file.read_bytes() == b"screenshot"
        if self.fail_add:
            raise SoarAPIError("vault unavailable")
        return "vault-id"

    def get_attachment(self, **_kwargs):
        return [
            SimpleNamespace(
                vault_id="vault-id",
                name="screenshot.png",
                id=7,
                container_id=42,
                size=10,
            )
        ]


def write_screenshot(_endpoint, destination, _max_size):
    destination.write(b"screenshot")
    return "image/png", "/screenshots/example.png"


def test_screenshot_vaults_streamed_file_and_removes_temporary_file(tmp_path, mocker):
    vault = Vault(tmp_path)
    soar = SimpleNamespace(
        vault=vault,
        get_executing_container_id=lambda: 42,
        set_message=lambda _message: None,
        set_summary=lambda _summary: None,
    )
    client = mocker.Mock()
    client.download_screenshot.side_effect = write_screenshot
    mocker.patch("src.actions.screenshot.UrlscanClient.from_asset", return_value=client)

    result = run_get_screenshot(
        SimpleNamespace(report_id="example", container_id=42),
        soar,
        SimpleNamespace(max_screenshot_size_mb=URLSCAN_DEFAULT_MAX_SCREENSHOT_SIZE_MB),
    )

    assert result.vault_id == "vault-id"
    assert vault.added_file is not None
    assert not vault.added_file.exists()


def test_screenshot_removes_temporary_file_when_vaulting_fails(tmp_path, mocker):
    vault = Vault(tmp_path, fail_add=True)
    soar = SimpleNamespace(vault=vault, get_executing_container_id=lambda: 42)
    client = mocker.Mock()
    client.download_screenshot.side_effect = write_screenshot
    mocker.patch("src.actions.screenshot.UrlscanClient.from_asset", return_value=client)

    with pytest.raises(ActionFailure, match="vault unavailable"):
        run_get_screenshot(
            SimpleNamespace(report_id="example", container_id=42),
            soar,
            SimpleNamespace(
                max_screenshot_size_mb=URLSCAN_DEFAULT_MAX_SCREENSHOT_SIZE_MB
            ),
        )

    assert vault.added_file is not None
    assert not vault.added_file.exists()
