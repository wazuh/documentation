.. Copyright (C) 2020 Wazuh, Inc.

.. _syscheck_update:

syscheck_update
===============

.. deprecated:: 3.7.0

The syscheck_update program wipes the integrity check database. All information about files that were added to the integrity check database will be deleted leaving an empty database which will be populated again the next time the syscheck daemon runs on the agents or the server.

+------------------------+--------------------------------------------------------------------+
| **-h**                 | Display the help message.                                          |
+------------------------+--------------------------------------------------------------------+
| **-l**                 | List the available agents.                                         |
+------------------------+--------------------------------------------------------------------+
| **-a**                 | Update the database for all agents.                                |
+------------------------+--------------------------------------------------------------------+
| **-u <id> / -u local** | Update the database for the specified agent or the local database. |
+------------------------+--------------------------------------------------------------------+
