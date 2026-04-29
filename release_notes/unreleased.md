**Unreleased**

* Migrate urlscan connector from legacy BaseConnector to Splunk SOAR SDK
* Add new `make request` action for executing arbitrary API calls against the urlscan.io REST API
* Change legacy polling-timeout behavior so `get report` and `detonate url` now fail when a report never becomes available, instead of returning a misleading success status
