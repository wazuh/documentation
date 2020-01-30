.. Copyright (C) 2019 Wazuh, Inc.

.. _release_3_11_2:

3.11.2 Release notes
====================

This section lists the changes in version 3.11.2. More details about these changes are provided in each component changelog:

- `wazuh/wazuh <https://github.com/wazuh/wazuh/blob/v3.11.2/CHANGELOG.md>`_
- `wazuh/wazuh-kibana-app <https://github.com/wazuh/wazuh-kibana-app/blob/v3.11.2-7.5.2/CHANGELOG.md>`_

Wazuh core
----------

**Security Configuration Assessment**

- Fixed handler leaks on SCA module for Windows agents.

**Vulnerability Detector**

- The module needed around 1 GB memory during the NVD feed fetch. The memory usage now remains on a few hundred MBs.

**Rootcheck**

- Fixed bug on Rootcheck scan that led to 100% CPU usage spikes. The ``<readall>`` option was wrongly applied, even when disabled.
- Fixed handler leaks on Rootcheck module for Windows agents.

**Other fixes and improvements**

- Fixed a memory leak in Clusterd: the RAM usage was steadily climbing through the days until the memory was exhausted.
- Ruleset update lead to incorrect ``VERSION`` file permissions.
- The Slack integration now correctly handles alerts with no description.

Wazuh UI for Kibana
-------------------

- Increased list filesize limit for the CDB-list.
- The XML validator now correctly handles the ``--`` string within comments.
