.. Copyright (C) 2020 Wazuh, Inc.

.. meta:: :description: Learn how to install Elastic Stack for using Wazuh on Debian

.. _kibana:


Kibana
======

Kibana is a flexible and intuitive web interface for mining and visualizing the events and archives stored in Elasticsearch. More information can be found at `Elastic Kibana site <https://www.elastic.co/products/kibana>`_.

Elastic recommends installing Kibana on the same server as Elasticsearch, but it is not required. The following Kibana installation may vary depending on whether Kibana will be installed in the same server as Elasticsearch or not.

Adding the Elastic Stack repository
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. tabs::


  .. group-tab:: APT


    .. include:: ../../_templates/installations/elastic/deb/add_repository.rst



  .. group-tab:: Yum


    .. include:: ../../_templates/installations/elastic/yum/add_repository.rst



  .. group-tab:: ZYpp


    .. include:: ../../_templates/installations/elastic/zypp/add_repository.rst



Kibana installation and configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Install the Kibana package:

    .. tabs::

        .. group-tab:: APT


            .. include:: ../../_templates/installations/elastic/deb/install_kibana.rst



        .. group-tab:: Yum


            .. include:: ../../_templates/installations/elastic/yum/install_kibana.rst



        .. group-tab:: ZYpp


            .. include:: ../../_templates/installations/elastic/zypp/install_kibana.rst


#. The next step, involving the certificate placement, may vary depending on whether Kibana will be installed in the same server as Elasticsearch or in a different one:


    .. tabs::



        .. tab:: Same Elasticsearch server


            Copy the Elasticsearch certificates:

            .. include:: ../../_templates/installations/elastic/common/copy_certificates_kibana_elastic_server.rst



        .. tab:: Different Elasticsearch server


            .. include:: ../../_templates/installations/elastic/common/generate_new_kibana_certificates.rst



#. Download the Kibana configuration file:

    .. include:: ../../_templates/installations/elastic/common/configure_kibana.rst


#. Install the Wazuh Kibana plugin:

    The installation of the plugin must be done from the Kibana home directory.

    .. code-block:: console

        # cd /usr/share/kibana

    .. code-block:: console

        # sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-3.11.4_7.6.0.zip

#. Enable and start the Kibana service:

    .. include:: ../../_templates/installations/elastic/common/enable_kibana.rst

    With the first access to Kibana, the browser shows a warning message stating that the certificate was not issued by a trusted authority. This can be accepted by clicking on ``Advanced options`` to add an exception or, for increased security, by importing the ``ca.crt`` previously created to the Certificate Manager of each browser that will access the Kibana interface.

    .. note:: The Kibana service listens to the default port 5601. The browser address will be: ``https://<kibana_ip>:5601`` replacing <kibana_ip> by the Kibana server IP.

Disabling repositories
~~~~~~~~~~~~~~~~~~~~~~

.. include:: ../../_templates/installations/elastic/common/disabling_repositories_explanation.rst


.. tabs::


  .. group-tab:: APT


    .. include:: ../../_templates/installations/elastic/deb/disabling_repositories.rst



  .. group-tab:: Yum


    .. include:: ../../_templates/installations/elastic/yum/disabling_repositories.rst



  .. group-tab:: ZYpp


    .. include:: ../../_templates/installations/elastic/zypp/disabling_repositories.rst


Next steps
~~~~~~~~~~

Once the Wazuh - Elastic Stack environment is ready, a Wazuh agent can be installed in every endpoint to be monitored. The Wazuh installation guide is available for most operating systems and it can be found :ref:`here<installation_agents>`.

Uninstall Kibana
~~~~~~~~~~~~~~~~

To uninstall Kibana:

.. tabs::


  .. group-tab:: APT


    .. include:: ../../_templates/installations/elastic/deb/uninstall_kibana.rst



  .. group-tab:: Yum


    .. include:: ../../_templates/installations/elastic/yum/uninstall_kibana.rst



  .. group-tab:: ZYpp


    .. include:: ../../_templates/installations/elastic/zypp/uninstall_kibana.rst
