.. Copyright (C) 2019 Wazuh, Inc.

.. _compatibility_matrix:

Compatibility matrix
====================


.. Wazuh software can be installed in many operating systems, you can check the compatibility matrix, which indicates what OS and Wazuh versions are compatible with your systems.

Wazuh software can be installed in many operating systems. Moreover, there's also specific compatibility requirements between different Wazuh products. In order to assist you, check the following compatibility matrix.

- `Operating system compatibility`_
- `Product compatibility`_

Operating system compatibility
------------------------------

Wazuh manager
^^^^^^^^^^^^^

Below it shown the compatibility table for the Wazuh manager.

+-----------------------------------+------------------------------------------+
|                                   |   **Wazuh version**                      |
+    **Operating System**           +------------------------+--------+--------+
|                                   |  From 3.0.x to current |  2.1.1 |  2.1.0 |
+-----------------------------------+------------------------+--------+--------+
|   Amazon Linux 1 or newer         |       ✓                |   ✓    |   ✓    |
+-----------------------------------+------------------------+--------+--------+
|   CentOS 6 and 7                  |       ✓                |   ✓    |   ✓    |
+-----------------------------------+------------------------+--------+--------+
|   Debian Wheezy/7 or newer        |       ✓                |   ✓    |   ✓    |
+-----------------------------------+------------------------+--------+--------+
|   Fedora (>= 22)                  |       ✓                |   ✓    |   ✓    |
+-----------------------------------+------------------------+--------+--------+
|   OpenSUSE 42, 15 and Tumbleweed *|       ✓                |   ✗    |   ✗    |
+-----------------------------------+------------------------+--------+--------+
|   Oracle Linux 6 and 7            |       ✓                |   ✗    |   ✗    |
+-----------------------------------+------------------------+--------+--------+
|   RHEL 6 and 7                    |       ✓                |   ✓    |   ✓    |
+-----------------------------------+------------------------+--------+--------+
|   SUSE 12 *                       |       ✓                |   ✗    |   ✗    |
+-----------------------------------+------------------------+--------+--------+
|   Ubuntu Precise/12.04 - 16.10    |       ✓                |   ✓    |   ✓    |
+-----------------------------------+------------------------+--------+--------+
|   Ubuntu Zesty/17.04 or newer     |       ✓                |   ✗    |   ✗    |
+-----------------------------------+------------------------+--------+--------+


*(\*) SUSE based host are available as Wazuh manager since Wazuh v3.2.1 version.*

Wazuh agent
^^^^^^^^^^^

In this table, you can check our supported OS list where the Wazuh agent can be installed.

+------------------------------------+-------------------------+
|                                    |**Wazuh version**        |
+       **Operating System**         +-------------------------+
|                                    |  From 3.3.1 to current  |
+------------------------------------+-------------------------+
|   AIX 5, 6 and 7                   |   ✓                     |
+------------------------------------+-------------------------+
|   Amazon Linux, Amazon Linux 2     |   ✓                     |
+------------------------------------+-------------------------+
|   CentOS 5, 6 and 7                |   ✓                     |
+------------------------------------+-------------------------+
|   Debian Wheezy/7 or newer         |   ✓                     |
+------------------------------------+-------------------------+
|   Fedora 22 or newer               |   ✓                     |
+------------------------------------+-------------------------+
|   HP-UX 11.31                      |   ✓                     |
+------------------------------------+-------------------------+
|   macOS Sierra or newer *          |   ✓                     |
+------------------------------------+-------------------------+
|   OpenSUSE 42, 15, Tumbleweed      |   ✓                     |
+------------------------------------+-------------------------+
|   Oracle Linux 5, 6 and 7          |   ✓                     |
+------------------------------------+-------------------------+
|   RHEL 5, 6 and 7                  |   ✓                     |
+------------------------------------+-------------------------+
|   Solaris 10 and 11 - i386 / sparc |   ✓                     |
+------------------------------------+-------------------------+
|   Suse 11 and 12                   |   ✓                     |
+------------------------------------+-------------------------+
|   Ubuntu Precise/12.04 or newer    |   ✓                     |
+------------------------------------+-------------------------+
|   Windows XP or newer              |   ✓                     |
+------------------------------------+-------------------------+
|   Windows Server 2003 or newer     |   ✓                     |
+------------------------------------+-------------------------+

\* With the release of macOS Catalina the packages are required to go through notarization. Version 3.10.2 was the first version to be notarized, this means that packages for versions older than 3.10.2 are not compatible with macOs Catalina.




Product compatibility
---------------------

When using the full stack of Wazuh software (that means, ``wazuh-manager``, ``wazuh-agent``, ``wazuh-api`` and ``wazuh-app``), there are different compatibility requirements in order to make everything work properly.

Manager and agents
^^^^^^^^^^^^^^^^^^

The compatibility between Wazuh agent and Wazuh manager is guaranteed when the Wazuh manager has a **newer or equal** version than the Wazuh agent.


.. note::

    The Wazuh manager is also compatible with **OSSEC agents**, but keep in mind that not all the capabilities will be available for them.

Manager and API
^^^^^^^^^^^^^^^

The API requires the same ``major.minor`` version as the Wazuh manager in order to be compatible.


API and Kibana app
^^^^^^^^^^^^^^^^^^

The Wazuh app for Kibana requires compatibility between two different products:

  - With the **Wazuh API**, it requires the same ``major.minor`` version.
  - With the **Elastic Stack**, it's only compatible with the exact same version.

+-----------------------------------+---------------------------+
|                                   |                           |
+    **API and Wazuh App version**  + **Elastic Stack version** +
|                                   |                           |
+-----------------------------------+---------------------------+
|              3.10.x               |      6.8.2 to 7.5.1       |
+-----------------------------------+---------------------------+
|              3.9.x                |      6.7.1 to 7.3.0       |
+-----------------------------------+---------------------------+
|              3.8.x                |      6.5.4 to 6.7.1       |
+-----------------------------------+---------------------------+
|              3.7.x                |      6.4.2 to 6.5.4       |
+-----------------------------------+---------------------------+
|              3.6.x                |      6.3.2 to 6.4.3       |
+-----------------------------------+---------------------------+
|              3.5.x                |      6.3.2 to 6.4.0       |
+-----------------------------------+---------------------------+
|              3.4.x                |      6.3.1 to 6.3.2       |
+-----------------------------------+---------------------------+
|              3.3.x                |      6.2.4 to 6.3.1       |
+-----------------------------------+---------------------------+
|              3.2.x                |      6.1.0 to 6.2.4       |
+-----------------------------------+---------------------------+
|              3.1.x                |      6.1.0 to 6.1.3       |
+-----------------------------------+---------------------------+
|              3.0.x                |      6.0.0 to 6.1.0       |
+-----------------------------------+---------------------------+
|              2.1.1                |           5.6.5           |
+-----------------------------------+---------------------------+

You can find more information on the `Wazuh app for Kibana repository <https://github.com/wazuh/wazuh-kibana-app#installation>`_, where you can check a more detailed compatibility matrix between the Wazuh app and Elastic Stack versions.

API and Splunk app
^^^^^^^^^^^^^^^^^^

The Splunk app for Wazuh requires compatibility between two different products:

  - With the **Wazuh API**, it requires the same ``major.minor`` version.
  - With **Splunk**, it's only compatible with the exact same version.

+---------------------------------+---------------------------+
|                                 |                           |
+ **API and Splunk App version**  +    **Splunk version**     +
|                                 |                           |
+---------------------------------+---------------------------+
|              3.10.x             |      7.3.0 to 8.0.0       |
+---------------------------------+---------------------------+
|              3.9.x              |      7.2.5 to 7.3.0       |
+---------------------------------+---------------------------+
|              3.8.x              |      7.2.3 to 7.2.6       |
+---------------------------------+---------------------------+
|              3.7.x              |      7.2.0 to 7.2.1       |
+---------------------------------+---------------------------+
|              3.6.x              |      7.1.2 to 7.1.3       |
+---------------------------------+---------------------------+
|              3.5.x              |      7.1.2                |
+---------------------------------+---------------------------+
|              3.4.x              |      7.1.2                |
+---------------------------------+---------------------------+
|              3.3.x              |      7.1.1                |
+---------------------------------+---------------------------+
|              3.2.x              |      7.0.3 to 7.1.1       |
+---------------------------------+---------------------------+


You can find more information on the `Wazuh app repository <https://github.com/wazuh/wazuh-splunk#installation>`_, where you can check a more detailed compatibility matrix between the Wazuh app for Splunk and Splunk versions.
