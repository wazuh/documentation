.. Copyright (C) 2020 Wazuh, Inc.

.. _wazuh-integratord:

wazuh-integratord
=================

.. versionadded:: 4.2

The ``wazuh-integratord`` is a daemon that allows Wazuh to connect to external APIs and alerting tools such as Slack, VirusTotal and PagerDuty.

For further details please refer to the following :ref:`page <manual_integration>`.

wazuh-integratord options
-------------------------

+-----------------+-------------------------------+
| **-d**          | Basic debug mode.             |
+-----------------+-------------------------------+
| **-dd**         | Verbose debug mode.           |
+-----------------+-------------------------------+
| **-f**          | Run in foreground.            |
+-----------------+-------------------------------+
| **-h**          | Display the help message.     |
+-----------------+-------------------------------+
| **-V**          | Version and license message.  |
+-----------------+-------------------------------+
| **-t**          | Test configuration.           |
+-----------------+-------------------------------+
| **-u <user>**   | Run as 'user'                 |
+-----------------+-------------------------------+
| **-g <group>**  | Run as 'group'                |
+-----------------+-------------------------------+
| **-c <config>** | Read the 'config' file        |
+-----------------+-------------------------------+
| **-D <dir>**    | Chroot to 'dir'               |
+-----------------+-------------------------------+
