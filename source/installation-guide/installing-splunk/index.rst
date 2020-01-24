.. Copyright (C) 2019 Wazuh, Inc.

.. _installation_splunk:

Installing Splunk
=================

.. meta::
  :description: Wazuh can be integrated with Splunk Enterprise to visualize alerts using our app. Learn more about how to install it.

To learn more about how Splunk works, here is their documentation: `Splunk <https://docs.splunk.com/Documentation>`_

This guide describes the Splunk Enterprise installation process for two different types of distributed architecture, along with the Splunk forwarder and the Wazuh app for Splunk.

- The **single-instance architecture** is recommended for testing and evaluation purposes, or also for small-medium sized environments.
- The **Splunk Cluster architecture** is recommended to replicate data along different indexes and make distributed searches.

+------------------------------------------------------------------------+-------------------------------------------------------------+
| Installation type                                                      | Description                                                 |
+========================================================================+=============================================================+
| :ref:`Single-instance installation <splunk_basic>`                     | Install Splunk using the single-instance architecture.      |
+------------------------------------------------------------------------+-------------------------------------------------------------+
| :ref:`Splunk Cluster installation <splunk_distributed>`                | Install a Cluster with Splunk multi-instance architecture.  |
+------------------------------------------------------------------------+-------------------------------------------------------------+

Find more information about how to scale your environments using Splunk Enterprise on the `official documentation <http://docs.splunk.com/Documentation/Splunk/8.0.0/Deploy/Distributedoverview>`_.

.. warning::
  The Wazuh app for Splunk requires the installation of a **Wazuh manager** and **Wazuh API** in order to work properly. Check out the :ref:`installation guide <wazuh_server_installation>` before proceeding with Splunk.

.. note::
  On Linux systems, the Splunk software **requires a 64-bit version** of the operating system. Although Splunk can be installed on different OS, the Splunk app is **only compatible with Linux systems**.

.. topic:: Contents

  .. toctree::
    :maxdepth: 1

    splunk-basic
    splunk-distributed
    splunk-app
    splunk-forwarder
    splunk-reverse-proxy
    splunk-polling
