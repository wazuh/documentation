.. Copyright (C) 2015, Wazuh, Inc.

.. meta::
  :description: Wazuh 4.7.0 has been released. Check out our release notes to discover the changes and additions of this release.

4.7.0 Release notes - 27 November 2023
======================================

This section lists the changes in version 4.7.0. Every update of the Wazuh solution is cumulative and includes all enhancements and fixes from previous releases.

What's new
----------

This version includes new features or improvements, such as the following:

Manager
^^^^^^^
- `#18026 <https://github.com/wazuh/wazuh/pull/18026>`__ Added native Maltiverse integration. Wazuh now leverages the Maltiverse API to enrich alerts. This enhancement supplements alert details with threat intelligence data following the Elastic Common Schema (ECS) standard. Acknowledgments to David Gil (`@dgilm <https://github.com/dgilm>`__).
- `#16090 <https://github.com/wazuh/wazuh/pull/16090>`__ Added an option to customize the Slack integration.
- `#16008 <https://github.com/wazuh/wazuh/pull/16008>`__ An unnecessary sanity check related to Syscollector has been removed from ``wazuh-db``.
- `#18570 <https://github.com/wazuh/wazuh/pull/18570>`__ Added support for Amazon Linux 2023 in Vulnerability Detector.
- `#20367 <https://github.com/wazuh/wazuh/pull/20367>`__ The manager now rejects agents with a higher version by default.

Agent
^^^^^

- `#17951 <https://github.com/wazuh/wazuh/pull/17951>`__ Added support for Custom AWS Logs in Buckets via AWS SQS. This enhancement improves visibility and troubleshooting in AWS environments.
- `#15582 <https://github.com/wazuh/wazuh/pull/15582>`__ Added geolocation for ``aws.data.client_ip`` field. The new GeoIP feature enables tracking of geographical locations of AWS ALB client IP addresses. This addition enhances visibility into network traffic and security monitoring. Acknowledgements to Arran Rhodes `@rh0dy <https://github.com/rh0dy>`__.
- `#15699 <https://github.com/wazuh/wazuh/pull/15699>`__ Added package inventory support for Alpine Linux in Syscollector.
- `#16117 <https://github.com/wazuh/wazuh/pull/16117>`__ Added package inventory support for MacPorts package manager in Syscollector. This enhancement improves compatibility with macOS.
- `#17982 <https://github.com/wazuh/wazuh/pull/17982>`__ Added package inventory support for Python PYPI and Node.js in Syscollector.
- `#15000 <https://github.com/wazuh/wazuh/pull/15000>`__ Added process information to the open ports inventory in Syscollector. This addition enhances ports inventory capabilities for better management and tracking on Linux systems.
- `#17966 <https://github.com/wazuh/wazuh/pull/17966>`__ The shared modules code has been sanitized according to the convention.
- `#18006 <https://github.com/wazuh/wazuh/pull/18006>`__ The package inventory internal messages have been modified to honor the schema compliance.
- `#20360 <https://github.com/wazuh/wazuh/pull/20360>`__ Added clarification to the agent connection log. The agent must connect to a manager of the same or higher version.

Wazuh dashboard
^^^^^^^^^^^^^^^

- `#5680 <https://github.com/wazuh/wazuh-dashboard-plugins/pull/5680>`__ Added the **Status detail** column in the **Agents** table.
- `#5738 <https://github.com/wazuh/wazuh-dashboard-plugins/pull/5738>`__ The agent registration wizard now effectively manages special characters in passwords.
- `#5636 <https://github.com/wazuh/wazuh-dashboard-plugins/pull/5636>`__ Changed the **Network ports** table columns for Linux agents.
- `#5707 <https://github.com/wazuh/wazuh-dashboard-plugins/pull/5707>`__ Changed Timelion-type displays in the **Management > Statistics** section to line-type displays.
- `#5747 <https://github.com/wazuh/wazuh-dashboard-plugins/pull/5747>`__ Removed views in JSON and XML formats from the **Management** settings.

RESTful API
^^^^^^^^^^^

- `#19726 <https://github.com/wazuh/wazuh/pull/19726>`__ Added new ``status_code`` field to ``GET /agents`` response.
- `#20126 <https://github.com/wazuh/wazuh/pull/20126>`__ Deprecated the following API endpoints.

  -  ``PUT /vulnerability``
  -  ``GET /vulnerability/{agent_id}``
  -  ``GET /vulnerability/{agent_id}/last_scan``
  -  ``GET /vulnerability/{agent_id}/summary/{field}``

Packages
^^^^^^^^

- `#2568 <https://github.com/wazuh/wazuh-packages/pull/2568>`__ Updated links to ``wazuh-dashboard-plugins`` repository.
- `#2555 <https://github.com/wazuh/wazuh-packages/pull/2555>`__ Added firewall validation to the installation assistant.

Resolved issues
---------------

This release resolves known issues as the following: 

Manager
^^^^^^^

==============================================================    =============
Reference                                                         Description
==============================================================    =============
`#16683 <https://github.com/wazuh/wazuh/pull/16683>`__            Fixed an unexpected cluster error when a worker gets restarted.
`#16681 <https://github.com/wazuh/wazuh/pull/16681>`__            Fixed an issue that let the manager validate wrong XML configurations.
`#19869 <https://github.com/wazuh/wazuh/pull/19869>`__            Fixed default value for ``multiarch`` field in syscollector packages.
`#20081 <https://github.com/wazuh/wazuh/pull/20081>`__            Fixed WPK rollback rebooting the host in Windows agent.
==============================================================    =============

Agent
^^^^^

==============================================================    =============
Reference                                                         Description
==============================================================    =============
`#17006 <https://github.com/wazuh/wazuh/pull/17006>`__            Fixed detection of ``osquery 5.4.0+`` running outside the integration.
`#16089 <https://github.com/wazuh/wazuh/pull/16089>`__            Fixed vendor data in package inventory for Brew packages on macOS.
`#19811 <https://github.com/wazuh/wazuh/pull/19811>`__            Improved reliability of the signature verification mechanism.
==============================================================    =============

RESTful API
^^^^^^^^^^^

==============================================================    =============
Reference                                                         Description
==============================================================    =============
`#16489 <https://github.com/wazuh/wazuh/pull/16489>`__            Addressed error handling for ``non-utf-8`` encoded file readings.
`#16914 <https://github.com/wazuh/wazuh/pull/16914>`__            Resolved an issue in the ``WazuhException`` class that disrupted the API executor subprocess.
`#16918 <https://github.com/wazuh/wazuh/issues/16918>`__          Corrected an empty value problem in the API specification key.
==============================================================    =============

Other
^^^^^

==============================================================    =============
Reference                                                         Description
==============================================================    =============
`#17040 <https://github.com/wazuh/wazuh/pull/17040>`__            Fixed the signature of the internal function ``OSHash_GetIndex()``.
==============================================================    =============

Wazuh dashboard
^^^^^^^^^^^^^^^

=======================================================================    =============
Reference                                                                  Description
=======================================================================    =============
`#5591 <https://github.com/wazuh/wazuh-dashboard-plugins/pull/5591>`__     Fixed problem with new or missing columns in the **Agents** table.
`#5676 <https://github.com/wazuh/wazuh-dashboard-plugins/pull/5676>`__     Fixed the color of the agent name in the groups section in dark mode.
`#5597 <https://github.com/wazuh/wazuh-dashboard-plugins/pull/5597>`__     Fixed the propagation event so that the flyout data, in the decoders, does not change when the button is pressed.
`#5631 <https://github.com/wazuh/wazuh-dashboard-plugins/pull/5631>`__     Fixed the tooltips of the tables in the **Security** section, and removed unnecessary requests.
=======================================================================    =============

Packages
^^^^^^^^

==============================================================     =============
Reference                                                          Description
==============================================================     =============
`#2523 <https://github.com/wazuh/wazuh-packages/pull/2523>`__      Fixed wrong condition when generating the RPM Wazuh indexer package with an existent base file.
==============================================================     =============

Changelogs
----------

More details about these changes are provided in the changelog of each component:

-  `wazuh/wazuh <https://github.com/wazuh/wazuh/blob/v4.7.0/CHANGELOG.md>`__
-  `wazuh/wazuh-dashboard <https://github.com/wazuh/wazuh-dashboard-plugins/blob/v4.7.0-2.8.0/CHANGELOG.md>`__
-  `wazuh/wazuh-packages <https://github.com/wazuh/wazuh-packages/releases/tag/v4.7.0>`__