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
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.models.view import ViewContext


class ViewTaskOutput(ActionOutput):
    uuid: str | None = OutputField(
        cef_types=["urlscan submission id"],
        example_values=["f04f2a29-d455-4830-874a-88191fb79352"],
    )


class ViewPageOutput(ActionOutput):
    ip: str | None = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    city: str | None = OutputField(example_values=["Bursa"])
    country: str | None = OutputField(example_values=["TR"])


class DetonateViewOutput(ActionOutput):
    requested_url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.yahoo.com"]
    )
    requested_get_result: bool | None
    uuid: str | None = OutputField(
        cef_types=["urlscan submission id"],
        example_values=["f04f2a29-d455-4830-874a-88191fb79352"],
    )
    task: ViewTaskOutput | None
    page: ViewPageOutput | None


class GetReportViewOutput(ActionOutput):
    task: ViewTaskOutput | None
    page: ViewPageOutput | None


class GetScreenshotViewOutput(ActionOutput):
    report_id: str | None = OutputField(
        cef_types=["urlscan submission id"],
        example_values=["f04f2a29-d455-4830-874a-88191fb79352"],
    )
    vault_id: str | None = OutputField(
        example_values=[
            "0599692c5298dd88f731960c55299f8de3331cf1"  # pragma: allowlist secret
        ]
    )
    name: str | None = OutputField(
        example_values=["cf9412df-963e-46a2-849b-de693d055b7b.png"]
    )
    file_type: str | None = OutputField(example_values=["image/png"])
    id: int | None = OutputField(example_values=[722])
    container_id: int | None = OutputField(example_values=[2390])
    size: int | None = OutputField(example_values=[13841])


def render_detonate_url(
    _context: ViewContext, outputs: list[DetonateViewOutput]
) -> dict:
    rows = []
    for output in outputs:
        rows.append(
            {
                "url": output.requested_url,
                "uuid": output.task.uuid
                if output.task and output.task.uuid
                else output.uuid,
                "ip": output.page.ip if output.page else None,
                "city": output.page.city if output.page else None,
                "country": output.page.country if output.page else None,
                "show_result_columns": bool(output.requested_get_result),
            }
        )
    return {"rows": rows}


def render_get_report(
    _context: ViewContext, outputs: list[GetReportViewOutput]
) -> dict:
    rows = []
    for output in outputs:
        rows.append(
            {
                "uuid": output.task.uuid if output.task else None,
                "ip": output.page.ip if output.page else None,
                "city": output.page.city if output.page else None,
                "country": output.page.country if output.page else None,
            }
        )
    return {"rows": rows}


def render_get_screenshot(
    _context: ViewContext, outputs: list[GetScreenshotViewOutput]
) -> dict:
    rows = []
    for output in outputs:
        rows.append(
            {
                "report_id": output.report_id,
                "vault_id": output.vault_id,
                "name": output.name,
                "file_type": output.file_type,
                "id": output.id,
                "container_id": output.container_id,
            }
        )
    return {"rows": rows}
