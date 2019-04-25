.. Copyright (C) 2019 Wazuh, Inc.

.. _upgrading_same_major:

Upgrade from the same major version (2.x)
=========================================

Use these instructions if you are upgrading your Wazuh installation within the same major version. For example, from 2.0.1 to 2.1.1.

Upgrade the Wazuh manager
-------------------------

Before upgrading the Wazuh manager, stop ``ossec-authd`` to ensure that it is not running in the background. Since Wazuh 2.1.0, ``ossec-authd`` should be configured in the :doc:`auth section <../../user-manual/reference/ossec-conf/auth>` of ``ossec.conf``.


a) Upgrade the Wazuh server on CentOS/RHEL/Fedora:

.. code-block:: console

    # yum upgrade wazuh-manager

b) Upgrade the Wazuh server on Debian/Ubuntu:

.. code-block:: console

    # apt-get update && sudo apt-get install wazuh-manager

Upgrade the Wazuh API
---------------------

a) Upgrade the Wazuh API on CentOS/RHEL/Fedora:

.. code-block:: console

    # yum upgrade wazuh-api

b) Upgrade the Wazuh API on Debian/Ubuntu:

.. code-block:: console

    # apt-get update && sudo apt-get install wazuh-api


Upgrade the Wazuh agent
-----------------------

a) Upgrade the Wazuh agent on CentOS/RHEL/Fedora:

.. code-block:: console

    # yum upgrade wazuh-agent

b) Upgrade the Wazuh agent on Debian/Ubuntu:

.. code-block:: console

    # apt-get update && sudo apt-get install wazuh-agent


Upgrade the Wazuh Kibana App
----------------------------

1) On your terminal, remove the current Wazuh Kibana App:

  a) Update file permissions. This will avoid several errors prior to updating the app:

    .. code-block:: console

      # chown -R kibana:kibana /usr/share/kibana/optimize
      # chown -R kibana:kibana /usr/share/kibana/plugins

  b) Remove the Wazuh app:

    .. code-block:: console

      # sudo -u kibana /usr/share/kibana/bin/kibana-plugin remove wazuh

2) Once the process is complete, stop Kibana:

  a) For Systemd:

    .. code-block:: console

        # systemctl stop kibana

  b) For SysV Init:

    .. code-block:: console

        # service kibana stop

3) Remove the current Kibana bundles:

.. code-block:: console

    # rm -rf /usr/share/kibana/optimize/bundles

4) Upgrade the Wazuh Kibana App (this can take a while):

  a) With sudo:

    .. code-block:: console

        # sudo -u kibana NODE_OPTIONS="--max-old-space-size=3072" /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-2.1.1_5.6.5.zip

  b) Without sudo:

    .. code-block:: console

        # su -c 'NODE_OPTIONS="--max-old-space-size=3072" /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-2.1.1_5.6.5.zip' kibana

5) Once the process is complete, restart Kibana:

  a) For Systemd:

    .. code-block:: console

        # systemctl start kibana

  b) For SysV Init:

    .. code-block:: console

        # service kibana start
