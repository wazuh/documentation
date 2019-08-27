.. Copyright (C) 2019 Wazuh, Inc.

.. _wazuh_agent_packages_linux_rpm_suse_11:

SUSE 11
=======

The RPM package is suitable for Suse 11. For other RPM-based OS (CentOS/RHEL, Fedora, Suse 12, OpenSUSE), please check the list: :doc:`Install Wazuh Agent on Linux <wazuh_agent_packages_linux>`.

.. note:: All the commands described below need to be executed with root user privileges.

Installing Wazuh agent
----------------------

1. Adding the Wazuh repository:

  .. code-block:: console

    # rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH-5
    # cat > /etc/zypp/repos.d/wazuh.repo <<\EOF
    [wazuh_repo]
    gpgcheck=1
    gpgkey=http://packages.wazuh.com/key/GPG-KEY-WAZUH-5
    enabled=1
    name=Wazuh repository
    baseurl=http://packages.wazuh.com/3.x/yum/5/$basearch/
    protect=1
    EOF

2. On your terminal, install the Wazuh agent. You can choose an installation or a deployment:

  a) Installation:

    .. code-block:: console

      # zypper install wazuh-agent

    Now that the agent is installed, the next step is to register and configure it to communicate with the manager. For more information about this process, please visit the document: :doc:`user manual<../../user-manual/registering/index>`.

  b) Deployment:

    You can automate the agent registration and configuration using variables. It is necessary to define at least the variable ``WAZUH_MANAGER_IP``. The agent will use this value to register and it will be the assigned manager for forwarding events.

    .. code-block:: console

      # WAZUH_MANAGER_IP="10.0.0.2" zypper install wazuh-agent

    See the following document for additional automated deployment options: :doc:`deployment variables <deployment_variables>`.

3. **(Optional)** Disable the Wazuh repository:

  We recommend maintaining the Wazuh Manager version greater or equal to that of the Wazuh Agents. As a result, we recommended disabling the Wazuh repository in order to prevent accidental upgrades. To do this, use the following command:

  .. code-block:: console

    # sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo

Alternatively, if you want to download the wazuh-agent package directly, or check the compatible versions, you can do it from :ref:`here <packages>`.

Uninstall
---------

To uninstall the agent:

    .. code-block:: console

      # zypper remove wazuh-agent

There are files marked as configuration files. Due to this designation, the package manager doesn't remove those files from the filesystem. The complete files removal action is a user responsibility. It can be done by removing the folder ``/var/ossec``.
