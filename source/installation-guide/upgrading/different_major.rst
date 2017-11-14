.. _upgrading_different_major:

Upgrade from different major version
=====================================

The following steps show how to upgrade from Wazuh 2.x to Wazuh 3.x, including a full upgrade of the Elastic Stack.

Before starting the upgrade is important to stop  Logstash service to avoid problems. 

.. code-block:: bash

    # systemctl stop logstash

Also, in order to upgrade Wazuh to 3.0 version, add the new repository. You can follow the instructions at :ref:`installation`.

Upgrade Wazuh manager
---------------------

Before upgrading Wazuh's manager, it is very important to stop ``ossec-authd`` in case that it is running in background.

a) Upgrade Wazuh manager on CentOS/RHEL/Fedora:

.. code-block:: bash

    # yum install wazuh-manager

b) Upgrade Wazuh manager on Debian/Ubuntu:

.. code-block:: bash
    # apt-get install wazuh-manager

Upgrade Wazuh API
---------------------

a) Upgrade Wazuh API on CentOS/RHEL/Fedora:

.. code-block:: bash

    # yum install wazuh-api

b) Upgrade Wazuh API on Debian/Ubuntu:

.. code-block:: bash
    # apt-get install wazuh-api

Upgrade Wazuh agent
---------------------

In order to upgrade Wazuh agents, you only need to add Wazuh's repository and upgrade the Wazuh agent.

a) Upgrade Wazuh agent on CentOS/RHEL/Fedora:

.. code-block:: bash

    # yum install wazuh-agent

b) Upgrade Wazuh agent on Debian/Ubuntu:

.. code-block:: bash
    # apt-get install wazuh-agent


Upgrade Elastic Stack
---------------------

In the new version of Wazuh, there's a change in the Wazuh alerts structure. Now, the new alerts bring more information to the final user. This means that a reindex of Wazuh's alerts in Elasticsearch is needed if you want to see old alerts in Kibana.

A reindex can be a tricky process, depending on how big is your dataset,  but we have created a script to automatize this process. 

1. Disable shard allocation:

.. code-block:: bash
    # curl -XPUT 'localhost:9200/_cluster/settings?pretty' -H 'Content-Type: application/json' -d'
    {
        "persistent": {
            "cluster.routing.allocation.enable": "none"
        }
    }
    '

2. Stop indexing and perform a synced flush:

.. code-block:: bash
    # curl -XPOST 'localhost:9200/_flush/synced?pretty'

3. Stop elasticsearch service. 

.. code-block:: bash
    # systemctl stop elasticsearch.service

4. Remove Wazuh Kibana App plugin from Kibana:

.. code-block:: bash
    # /usr/share/kibana/bin/kibana-plugin remove wazuh
    #  rm -rf /usr/share/kibana/optimize/bundles 

5. Add the last Elastic repository:

    a)  Add RPM repository:
    .. code-block:: bash
            # cat >> /etc/yum.repos.d/elastic.repo << EOF
            [elasticsearch-6.x]
            name=Elasticsearch repository for 6.x packages
            baseurl=https://artifacts.elastic.co/packages/6.x/yum
            gpgcheck=1
            gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
            enabled=1
            autorefresh=1
            type=rpm-md
            EOF

    b) Add APT repository:
    .. code-block:: bash
            # echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
            # apt-get update

6. Upgrade Elastic Stack to 6.0:
    a) Upgrade Elasticsearch:
    If you are using  CentOS/RHEL/Fedora:
    .. code-block:: bash
        # yum install elasticsearch 

    If you are using Debian/Ubuntu:
    .. code-block:: bash
        # apt-get install elasticsearch

    b) Upgrade Logstash:
    If you are using  CentOS/RHEL/Fedora:
    .. code-block:: bash
        # yum install logstash 

    If you are using Debian/Ubuntu:
    .. code-block:: bash
        # apt-get install logstash

    c) Upgrade Kibana:
    If you are using  CentOS/RHEL/Fedora:
    .. code-block:: bash
        # yum install kibana 

    If you are using Debian/Ubuntu:
    .. code-block:: bash
        # apt-get install kibana

7. Upgrade Wazuh Kibana App:
    .. code-block:: bash
     # /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp.zip

8. Restart elasticsearch node: 
    .. code-block:: bash
        # systemctl daemon-reload
        # systemctl restart elasticsearch

9. Reenable allocation:
    .. code-block:: bash
        # curl -XPUT 'localhost:9200/_cluster/settings?pretty' -H 'Content-Type: application/json' -d'
            {
              "persistent": {
                "cluster.routing.allocation.enable": "all"
              }
            }
            '

10. Load Wazuh Agent Elasticsearch template:

    .. code-block:: bash
        # curl https://url_of_wazuh_agent_templates/template.json |  curl -XPUT 'http://localhost:9200/_template/wazuh' -H 'Content-Type: application/json' -d @-

11. Load Wazuh Elasticsearch template:
    ..code-block:: bash
        # curl https://url_of_wazuh_templates/template.json |  curl -XPUT 'http://localhost:9200/_template/wazuh' -H 'Content-Type: application/json' -d @-

12. Reindex your old Wazuh alerts:
    a) Download our reindex script:
    ..code-block:: bash
        # curl -so /path/for/wazuh_elastic_reindex_index.sh https://github.com/wazuh/repository/...

    b) Reindex your data with ``wazuh_elastic_reindex_index.sh``. 
        .. code-block:: bash 
        #/path/for/wazuh_elastic_reindex_index.sh start_date end_date elasticsearch_ip

        You can see an example below:
        .. code-block:: bash 
        #/path/for/wazuh_elastic_reindex_index.sh 20171101 20171131 localhost

          .. warning::

          This process may take several amounts of time, depending on the size of your dataset.

    c) Restart elasticsearch:
    .. code-block:: bash
        # systemctl restart elasticsearch

13. Restart Logstash and Kibana
    .. code-block:: bash
        # systemctl restart logstash
        # systemctl restart kibana
