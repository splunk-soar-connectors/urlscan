**Unreleased**

* - Migrate urlscan connector from legacy BaseConnector to Splunk SOAR SDK
* - Change legacy polling-timeout behavior so `get report` and `detonate url` now fail when a report never becomes available, instead of returning a misleading success status
