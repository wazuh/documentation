.. Copyright (C) 2019 Wazuh, Inc.

.. _wazuh_server_packages_fedora:

Fedora from packages
====================

For Fedora 22 or greater, installing the Wazuh server components entails the installation of the relevant packages after adding the repositories.

.. note:: All the commands described below need to be executed with root user privileges.

Adding the Wazuh repository
---------------------------

The first step to setting up Wazuh is to add the Wazuh repository to your server. If you want to download the wazuh-manager package directly, or check the compatible versions, click :ref:`here <packages>`.

To set up the repository, run this command:

  .. code-block:: console

    # rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    # cat > /etc/yum.repos.d/wazuh.repo <<\EOF
    [wazuh_repo]
    gpgcheck=1
    gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
    enabled=1
    name=Wazuh repository
    baseurl=https://packages.wazuh.com/3.x/yum/
    protect=1
    EOF

.. note::

  From Fedora v22 to v25, it's required to install ``dkms`` package (``dnf install dkms``).

Installing the Wazuh manager
----------------------------

The next step is to install the Wazuh manager on your system:

  .. code-block:: console

    # dnf install wazuh-manager

Once the process is complete, you can check the service status with:

    * For Systemd:

      .. code-block:: console

        # systemctl status wazuh-manager

    * For SysV Init:

      .. code-block:: console

        # service wazuh-manager status

Installing the Wazuh API
------------------------

.. note::

  If you have Fedora v24 or lower, you need to add the official NodeJS repository previously:


    .. code-block:: console

      # curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -

1. Install NodeJS:

  .. code-block:: console

    # dnf install nodejs

2. Install the Wazuh API:

  .. code-block:: console

    # dnf install wazuh-api

3. Once the process is complete, you can check the service status with:

  * For Systemd:

    .. code-block:: console

      # systemctl status wazuh-api

  * For SysV Init:

    .. code-block:: console

      # service wazuh-api status

.. note::
    Now that the Wazuh API is installed, check out the section :ref:`securing_api` to set up some additional settings.

4. (Optional) Disable the Wazuh repository:

  It is recommended that the Wazuh repository be disabled in order to prevent accidental upgrades. To do this, use the following command:

  .. code-block:: console

    # sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo

.. _wazuh_server_packages_fedora_filebeat:

Installing Filebeat
-------------------

Filebeat is the tool on the Wazuh server that securely forwards alerts and archived events to Elasticsearch. To install it:

1. Add the Elastic repository and its GPG key:

  .. code-block:: console

    # rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
    # cat > /etc/yum.repos.d/elastic.repo << EOF
    [elasticsearch-7.x]
    name=Elasticsearch repository for 7.x packages
    baseurl=https://artifacts.elastic.co/packages/7.x/yum
    gpgcheck=1
    gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
    enabled=1
    autorefresh=1
    type=rpm-md
    EOF

2. Install Filebeat:

  .. code-block:: console

    # dnf install filebeat-7.5.1

3. Download the Filebeat configuration file from the Wazuh repository. This is pre-configured to forward Wazuh alerts to Elasticsearch:

  .. code-block:: console

    # curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/v3.10.2/extensions/filebeat/7.x/filebeat.yml
    # chmod go+r /etc/filebeat/filebeat.yml

4. Download the alerts template for Elasticsearch:

  .. code-block:: console

    # curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v3.10.2/extensions/elasticsearch/7.x/wazuh-template.json
    # chmod go+r /etc/filebeat/wazuh-template.json

5. Download the Wazuh module for Filebeat:

  .. code-block:: console

    # curl -s https://packages.wazuh.com/3.x/filebeat/wazuh-filebeat-0.1.tar.gz | sudo tar -xvz -C /usr/share/filebeat/module

6. Edit the file ``/etc/filebeat/filebeat.yml`` and replace ``YOUR_ELASTIC_SERVER_IP`` with the IP address or the hostname of the Elasticsearch server. For example:

  .. code-block:: yaml

    output.elasticsearch.hosts: ['http://YOUR_ELASTIC_SERVER_IP:9200']

7. Enable and start the Filebeat service:

  * For Systemd:

    .. code-block:: console

      # systemctl daemon-reload
      # systemctl enable filebeat.service
      # systemctl start filebeat.service

  * For SysV Init:

    .. code-block:: console

      # chkconfig --add filebeat
      # service filebeat start

8. (Optional) Disable the Elastic repository:

  It is recommended that the Elastic repository be disabled in order to prevent accidental upgrades. To do this, use the following command:

  .. code-block:: console

    # sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo

Next steps
----------

Once you have installed the manager, API and Filebeat, you are ready to install :ref:`Elastic Stack <installation_elastic>`.

Uninstall
---------

To uninstall the Wazuh manager and Wazuh API:

  .. code-block:: console

    # dnf remove wazuh-manager wazuh-api

There are files marked as configuration files. Due to this designation, the package manager doesn't remove those files from the filesystem. The complete files removal action is a user responsibility. It can be done by removing the folder ``/var/ossec``.

To uninstall filebeat:

  .. code-block:: console

      # dnf remove filebeat
