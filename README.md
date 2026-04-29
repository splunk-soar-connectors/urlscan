# urlscan.io

Publisher: Splunk <br>
Connector Version: 2.6.3 <br>
Product Vendor: urlscan.io <br>
Product Name: urlscan.io <br>
Minimum Product Version: 7.0.0

This app supports investigative actions on urlscan.io

The **api_key** field is not required to use this app, as **urlscan.io** does not require an API key
for querying its database. However, if you wish to start a scan with **detonate url** , then you
will need an API key configured.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Urlscan server. Below are the default
ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http | tcp | 80 |
|         https | tcp | 443 |

### Configuration variables

This table lists the configuration variables required to operate urlscan.io. These variables are specified when configuring a urlscan.io asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_key** | optional | password | API key for urlscan.io |
**timeout** | optional | numeric | Timeout period for action (seconds) |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration. <br>
[get report](#action-get-report) - Query for results of an already completed detonation <br>
[lookup domain](#action-lookup-domain) - Find information about a domain at urlscan.io <br>
[lookup ip](#action-lookup-ip) - Find information about an IP address at urlscan.io <br>
[detonate url](#action-detonate-url) - Detonate a URL at urlscan.io <br>
[get screenshot](#action-get-screenshot) - Retrieve copy of screenshot file <br>
[make request](#action-make-request) - Make an HTTP request to any urlscan.io API endpoint using the configured asset credentials.

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration.

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get report'

Query for results of an already completed detonation

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Detonation ID for the desired report | string | `urlscan submission id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | `urlscan submission id` | |
action_result.data.\*.page.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.page.city | string | | Bursa |
action_result.data.\*.page.country | string | | TR |
action_result.data.\*.page.domain | string | `domain` | yahoo.com |
action_result.data.\*.page.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.task.uuid | string | `urlscan submission id` | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.task.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.task.domain | string | | yahoo.com |
action_result.data.\*.stats.requests | numeric | | 69 |
action_result.data.\*.stats.took | numeric | | 25 |
action_result.data.\*.stats.total | numeric | | 1 |
action_result.summary.scan_uuid | string | | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.summary.page_domain | string | | yahoo.com |
action_result.summary.added_tags_num | numeric | | 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup domain'

Find information about a domain at urlscan.io

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to lookup | string | `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.domain | string | `domain` | |
action_result.data.\*.has_more | boolean | | True False |
action_result.data.\*.results.\*.page.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.page.city | string | | Bursa |
action_result.data.\*.results.\*.page.country | string | | TR |
action_result.data.\*.results.\*.page.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.page.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.results.\*.task.uuid | string | `urlscan submission id` | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.results.\*.task.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.results.\*.task.domain | string | | yahoo.com |
action_result.data.\*.results.\*.result | string | `url` | https://urlscan.io/api/v1/result/86b7f70a-5039-419f-9aeb-8cba09404e92 |
action_result.data.\*.results.\*.screenshot | string | `url` | https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png |
action_result.data.\*.results.\*.stats.requests | numeric | | 69 |
action_result.data.\*.results.\*.stats.took | numeric | | 25 |
action_result.data.\*.results.\*.stats.total | numeric | | 1 |
action_result.data.\*.took | numeric | | 25 |
action_result.data.\*.total | numeric | | 1 |
action_result.summary.total | numeric | | 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup ip'

Find information about an IP address at urlscan.io

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to lookup | string | `ip` `ipv6` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip | string | `ip` `ipv6` | |
action_result.data.\*.has_more | boolean | | True False |
action_result.data.\*.results.\*.page.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.results.\*.page.city | string | | Bursa |
action_result.data.\*.results.\*.page.country | string | | TR |
action_result.data.\*.results.\*.page.domain | string | `domain` | yahoo.com |
action_result.data.\*.results.\*.page.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.results.\*.task.uuid | string | `urlscan submission id` | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.results.\*.task.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.results.\*.task.domain | string | | yahoo.com |
action_result.data.\*.results.\*.result | string | `url` | https://urlscan.io/api/v1/result/86b7f70a-5039-419f-9aeb-8cba09404e92 |
action_result.data.\*.results.\*.screenshot | string | `url` | https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png |
action_result.data.\*.results.\*.stats.requests | numeric | | 69 |
action_result.data.\*.results.\*.stats.took | numeric | | 25 |
action_result.data.\*.results.\*.stats.total | numeric | | 1 |
action_result.data.\*.took | numeric | | 25 |
action_result.data.\*.total | numeric | | 1 |
action_result.summary.total | numeric | | 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'detonate url'

Detonate a URL at urlscan.io

Type: **investigate** <br>
Read only: **False**

If the get_result parameter is set to true, then the action may take up to 2-3 minutes to execute because the action will poll for the results in the same call.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to detonate | string | `url` `domain` |
**tags** | optional | Comma-separated list of tags to annotate this scan. Limited to 10 tags. Tags with lengths longer than 29 will be omitted | string | |
**private** | optional | Run a private scan | boolean | |
**custom_agent** | optional | Override User-Agent for this scan | string | |
**get_result** | optional | Get scan result in same call | boolean | |
**addto_vault** | optional | Add url screenshot to vault | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.url | string | `url` `domain` | |
action_result.parameter.tags | string | | |
action_result.parameter.private | boolean | | |
action_result.parameter.custom_agent | string | | |
action_result.parameter.get_result | boolean | | |
action_result.parameter.addto_vault | boolean | | |
action_result.data.\*.uuid | string | `urlscan submission id` | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.message | string | | Submission successful |
action_result.data.\*.description | string | | The submitted URL was blocked from scanning. |
action_result.data.\*.status | numeric | | 400 |
action_result.data.\*.requested_url | string | `url` | https://www.yahoo.com |
action_result.data.\*.requested_get_result | boolean | | True False |
action_result.data.\*.submitted_tags.\* | string | | ['test_tag1', 'test_tag2'] |
action_result.data.\*.omitted_tags.\* | string | | ['this_tag_is_longer_than_twenty_nine_chars'] |
action_result.data.\*.omitted_tags_num | numeric | | 1 |
action_result.data.\*.page.ip | string | `ip` `ipv6` | 8.8.8.8 |
action_result.data.\*.page.city | string | | Bursa |
action_result.data.\*.page.country | string | | TR |
action_result.data.\*.page.domain | string | `domain` | yahoo.com |
action_result.data.\*.page.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.task.uuid | string | `urlscan submission id` | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.task.url | string | `url` | https://www.yahoo.com |
action_result.data.\*.task.domain | string | | yahoo.com |
action_result.summary.added_tags_num | numeric | | 1 |
action_result.summary.omitted_tags_num | numeric | | 1 |
action_result.summary.vault_id | string | | 0599692c5298dd88f731960c55299f8de3331cf1 |
action_result.summary.name | string | | cf9412df-963e-46a2-849b-de693d055b7b.png |
action_result.summary.file_type | string | | image/png |
action_result.summary.id | numeric | | 722 |
action_result.summary.container_id | numeric | | 2390 |
action_result.summary.size | numeric | | 13841 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get screenshot'

Retrieve copy of screenshot file

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report_id** | required | UUID of report | string | `urlscan submission id` |
**container_id** | optional | Event to add file to, will default to current container id | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.report_id | string | `urlscan submission id` | |
action_result.parameter.container_id | numeric | | |
action_result.data.\*.report_id | string | `urlscan submission id` | f04f2a29-d455-4830-874a-88191fb79352 |
action_result.data.\*.vault_id | string | | 0599692c5298dd88f731960c55299f8de3331cf1 |
action_result.data.\*.name | string | | cf9412df-963e-46a2-849b-de693d055b7b.png |
action_result.data.\*.file_type | string | | image/png |
action_result.data.\*.id | numeric | | 722 |
action_result.data.\*.container_id | numeric | | 2390 |
action_result.data.\*.size | numeric | | 13841 |
action_result.summary.id | numeric | | 722 |
action_result.summary.name | string | | cf9412df-963e-46a2-849b-de693d055b7b.png |
action_result.summary.size | numeric | | 13841 |
action_result.summary.vault_id | string | | 0599692c5298dd88f731960c55299f8de3331cf1 |
action_result.summary.file_type | string | | image/png |
action_result.summary.container_id | numeric | | 2390 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'make request'

Make an HTTP request to any urlscan.io API endpoint using the configured asset credentials.

Type: **generic** <br>
Read only: **False**

'make request' action for the app. Used to handle arbitrary HTTP requests with the app's asset

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_method** | required | The HTTP method to use for the request. | string | |
**endpoint** | required | urlscan.io endpoint path, relative to https://urlscan.io. For example: 'api/v1/search/?q=domain:example.com' or 'api/v1/result/{uuid}'. | string | |
**headers** | optional | The headers to send with the request (JSON object). An example is {'Content-Type': 'application/json'} | string | |
**query_parameters** | optional | Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2 | string | |
**body** | optional | The body to send with the request (JSON object). An example is {'key': 'value', 'key2': 'value2'} | string | |
**timeout** | optional | The timeout for the request in seconds. | numeric | |
**verify_ssl** | optional | Whether to verify the SSL certificate. Default is False. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_method | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.headers | string | | |
action_result.parameter.query_parameters | string | | |
action_result.parameter.body | string | | |
action_result.parameter.timeout | numeric | | |
action_result.parameter.verify_ssl | boolean | | |
action_result.data.\*.status_code | numeric | | 200 |
action_result.data.\*.response_body | string | | {"results": [], "total": 0} |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
