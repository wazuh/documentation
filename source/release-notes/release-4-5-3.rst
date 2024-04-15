.. Copyright (C) 2015, Wazuh, Inc.

.. meta::
  :description: Wazuh 4.5.3 has been released. Check out our release notes to discover the changes and additions of this release.

4.5.3 Release notes - 10 October 2023
=====================================

This section lists the changes in version 4.5.3. Every update of the Wazuh solution is cumulative and includes all enhancements and fixes from previous releases.

What's new
----------

This version includes new features or improvements, such as the following:

Manager
^^^^^^^

-  `#18783 <https://github.com/wazuh/wazuh/pull/18783>`__ Vulnerability Detector now fetches the SUSE feeds in Gzip compressed format.

Agent
^^^^^

-  `#19205 <https://github.com/wazuh/wazuh/issues/19205>`__ Support for macOS 14 (Sonoma).

RESTful API
^^^^^^^^^^^

-  `#18509 <https://github.com/wazuh/wazuh/pull/18509>`__ Added support for the ``$`` symbol in query values.
-  `#18346 <https://github.com/wazuh/wazuh/pull/18346>`__ Added support for the ``@`` symbol in query values.
-  `#18493 <https://github.com/wazuh/wazuh/pull/18493>`__ Added support for nested queries in the ``q`` API parameter.
-  `#18432 <https://github.com/wazuh/wazuh/pull/18432>`__ Updated ``force`` flag message in the ``agent_upgrade`` CLI.

Security updates
----------------

This release fixes the following vulnerabilities:

Agent
^^^^^

==============    ========================================================    =============
CVE               Reference                                                   Description
==============    ========================================================    =============
CVE-2023-42463    `#19069 <https://github.com/wazuh/wazuh/pull/19069>`__      Fixed a stack overflow hazard in ``wazuh-logcollector`` that could allow a local privilege escalation. Found by Keith Yeo (`@kyeojy <https://twitter.com/kyeojy>`__).
==============    ========================================================    =============

Resolved issues
---------------

This release resolves known issues as the following:

Manager
^^^^^^^

========================================================    =============
Reference                                                   Description
========================================================    =============
`#18737 <https://github.com/wazuh/wazuh/pull/18737>`__      Fixed a bug that might cause ``wazuh-analysisd`` to crash if it receives a status API query during startup.
`#18976 <https://github.com/wazuh/wazuh/pull/18976>`__      Fixed a bug that might cause ``wazuh-maild`` to crash when handling large alerts.
`#19217 <https://github.com/wazuh/wazuh/pull/19217>`__      Addressed an issue in Vulnerability Detector when fetching the Suse Linux Enterprise 15 feeds.
========================================================    =============

Agent
^^^^^

========================================================    =============
Reference                                                   Description
========================================================    =============
`#18773 <https://github.com/wazuh/wazuh/pull/18773>`__      Fixed a bug in the memory handle at the agent's data provider helper.
`#18903 <https://github.com/wazuh/wazuh/pull/18903>`__      Fixed a data mismatch in the OS name between the global and agents' databases.
`#19286 <https://github.com/wazuh/wazuh/pull/19286>`__      Fixed wrong Windows agent binaries metadata.
`#19397 <https://github.com/wazuh/wazuh/pull/19397>`__      Fixed error during the Windows agent upgrade.
========================================================    =============

RESTful API
^^^^^^^^^^^

==============================================================    =============
Reference                                                         Description
==============================================================    =============
`#18362 <https://github.com/wazuh/wazuh/pull/18362>`__            Removed undesired characters when listing rule group names in ``GET /rules/groups``.
`#18434 <https://github.com/wazuh/wazuh/pull/18434>`__            Fixed an error when using the query ``condition=all`` in ``GET /sca/{agent_id}/checks/{policy_id}``.
`#18733 <https://github.com/wazuh/wazuh/pull/18733>`__            Fixed an error in the API log mechanism where sometimes the requests would not be printed in the log file.
==============================================================    =============

Wazuh dashboard
^^^^^^^^^^^^^^^

=======================================================================    =============
Reference                                                                  Description
=======================================================================    =============
`#5925 <https://github.com/wazuh/wazuh-dashboard-plugins/pull/5925>`__     Fixed the command for agent installation on SUSE to use zypper.
=======================================================================    =============

Wazuh Kibana plugin for Kibana 7.10.2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

=======================================================================    =============
Reference                                                                  Description
=======================================================================    =============
`#5925 <https://github.com/wazuh/wazuh-dashboard-plugins/pull/5925>`__     Fixed the command for agent installation on SUSE to use zypper.
=======================================================================    =============

Wazuh Kibana plugin for Kibana 7.16.x and 7.17.x
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

=======================================================================    =============
Reference                                                                  Description
=======================================================================    =============
`#5925 <https://github.com/wazuh/wazuh-dashboard-plugins/pull/5925>`__     Fixed the command for agent installation on SUSE to use zypper.
=======================================================================    =============

Packages
^^^^^^^^

===============================================================    =============
Reference                                                          Description
===============================================================    =============
`#2397 <https://github.com/wazuh/wazuh-packages/pull/2397>`__      Changed GRUB options in build OVA process.
`#2453 <https://github.com/wazuh/wazuh-packages/pull/2453>`__      Fixed  an issue with the Wazuh dashboard port check despite the ``-p|--port`` installation assistant option being specified.
`#2461 <https://github.com/wazuh/wazuh-packages/pull/2461>`__      Fixed an issue when passwords changed. Now the ``internal_users.yml`` file gets updated.
`#2492 <https://github.com/wazuh/wazuh-packages/pull/2492>`__      Fixed missing removal of Wazuh indexer remaining files upon rollback.
===============================================================    =============

Changelogs
----------

More details about these changes are provided in the changelog of each component:

-  `wazuh/wazuh <https://github.com/wazuh/wazuh/blob/v4.5.3/CHANGELOG.md>`_
-  `wazuh/wazuh-dashboard <https://github.com/wazuh/wazuh-dashboard-plugins/blob/v4.5.3-2.6.0/CHANGELOG.md>`_
-  `wazuh/wazuh-dashboard-plugins 7.10.2 <https://github.com/wazuh/wazuh-dashboard-plugins/blob/v4.5.3-7.10.2/CHANGELOG.md>`_
-  `wazuh/wazuh-dashboard-plugins 7.16.x <https://github.com/wazuh/wazuh-dashboard-plugins/blob/v4.5.3-7.16.3/CHANGELOG.md>`_
-  `wazuh/wazuh-dashboard-plugins 7.17.x <https://github.com/wazuh/wazuh-dashboard-plugins/blob/v4.5.3-7.17.13/CHANGELOG.md>`_
-  `wazuh/wazuh-splunk <https://github.com/wazuh/wazuh-splunk/blob/v4.5.3-8.2/CHANGELOG.md>`_
-  `wazuh/wazuh-packages <https://github.com/wazuh/wazuh-packages/releases/tag/v4.5.3>`_
