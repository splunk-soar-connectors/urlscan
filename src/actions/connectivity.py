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
from soar_sdk.asset import BaseAsset
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from ..constants import URLSCAN_TEST_CONNECTIVITY_ENDPOINT
from .action_utils import make_client

logger = getLogger()


def run_test_connectivity(asset: BaseAsset) -> None:
    """Validate the asset configuration for connectivity using supplied configuration."""
    client = make_client(asset)

    if client.api_key:
        logger.info("Validating API Key")
        response = client.request(
            URLSCAN_TEST_CONNECTIVITY_ENDPOINT,
            headers={"API-Key": client.api_key},
        )
    else:
        logger.info("No API key found, checking connectivity to urlscan.io")
        response = client.request(URLSCAN_TEST_CONNECTIVITY_ENDPOINT)

    if not response.ok:
        raise ActionFailure(response.message)

    logger.info("Test Connectivity Passed")
