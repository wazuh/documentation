.. _installation:

Installing Wazuh server
=================================

The Wazuh manager can be installed on any Unix-like operating system, most commonly Linux.  It is generally most convenient to install it via package, if one is available for your distribution.  However, building and installing it from source is also pretty simple.  In addition to Wazuh manager, Filebeat is also available to install in convenient package form onto your Wazuh server.

.. note::
        Installing Wazuh Server on a 64-bit operating system is highly recommended, since the Wazuh API is not available on 32-bit platforms.  Without the Wazuh API, much of the functionality of the Wazuh Kibana App will not work.  Similarly, if using Red Hat or CentOS for your Wazuh Server platform, make sure it is version 6 or higher so that the Wazuh API will be available.

+------------------------------------------------------------------------+-------------------------------------------------------------+
| Type                                                                   | Description                                                 |
+========================================================================+=============================================================+
| :ref:`Rpm packages <wazuh_server_rpm>`                                 | Install Wazuh server on CentOS/RHEL/Fedora.                 |
+------------------------------------------------------------------------+-------------------------------------------------------------+
| :ref:`Deb packages <wazuh_server_deb>`                                 | Install Wazuh server on Debian/Ubuntu.                      |
+------------------------------------------------------------------------+-------------------------------------------------------------+
| :ref:`Sources <sources_installation>`                                  | Install Wazuh server from source code.                      |
+------------------------------------------------------------------------+-------------------------------------------------------------+


.. topic:: Contents

    .. toctree::
       :maxdepth: 2

       packages-installation/index
       sources_installation
