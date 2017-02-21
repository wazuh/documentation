.. _installation_agents:

Installing agents
======================================================

There are several ways to install a Wazuh agent, depending on the operating system and whether or not you wish to build from source. Consult the table below and choose how to proceed for a given agent:

+-------------------------------------------------+--------------------------------------------------+
| Type                                            | Description                                      |
+=================================================+==================================================+
| :ref:`Rpm packages <wazuh_agent_rpm>`           | Install Wazuh agents on CentOS/RHEL/Fedora.      |
+-------------------------------------------------+--------------------------------------------------+
| :ref:`Deb packages <wazuh_agent_deb>`           | Install Wazuh agents on Debian/Ubuntu.           |
+-------------------------------------------------+--------------------------------------------------+
| :ref:`Windows installer <wazuh_agent_windows>`  | Install Wazuh agents on Windows.                 |
+-------------------------------------------------+--------------------------------------------------+
| :ref:`Sources <wazuh_agent_other>`              | Install Wazuh agents from source code.           |
+-------------------------------------------------+--------------------------------------------------+

Once we have our agents installed, it is necessary to connect them with the manager. Check out the :ref:`registration process <connecting_agents>`.

.. topic:: Contents

    .. toctree::
        :maxdepth: 2

        packages-installation/index
        windows/index
        sources/index
