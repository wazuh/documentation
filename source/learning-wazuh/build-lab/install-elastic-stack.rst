.. Copyright (C) 2020 Wazuh, Inc.

.. _build_lab_install_elastic_stack:

Install the Elastic Stack
=========================

Your Elastic Stack will be running Elasticsearch, Kibana and the Wazuh plugin for Kibana.

Log in and sudo to root
-----------------------

For the purposes of these labs, always become root when logging into a lab
machine via SSH.

    .. code-block:: console

      [centos@elastic-server ~]$ sudo su -
      [root@elastic-server ~]#



Preparation
-----------

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

2. Install unzip:

   .. code-block:: console

     # yum install -y unzip

Elasticsearch
-------------

Elasticsearch is a highly scalable full-text search and analytics engine that will
store alerts and log records sent by Wazuh via Filebeat and make them available
to Kibana. For more information, please see `Elasticsearch
<https://www.elastic.co/products/elasticsearch>`_.

1. Install the Elasticsearch package:

  .. code-block:: console

	 # yum -y install elasticsearch-|ELASTICSEARCH_LATEST|

2. Enable and start the Elasticsearch service:

  .. code-block:: console

  	# systemctl daemon-reload
  	# systemctl enable elasticsearch.service
  	# systemctl start elasticsearch.service

3. Optimize Elasticsearch for lab use according to :ref:`this guide <elastic_tuning>`.

  This process will set optimal index sharding, replication, and memory usage values for Elasticsearch.

  .. code-block:: none

    # sed -i 's/#bootstrap.memory_lock: true/bootstrap.memory_lock: true/' /etc/elasticsearch/elasticsearch.yml
    # mkdir -p /etc/systemd/system/elasticsearch.service.d/
    # echo -e "[Service]\nLimitMEMLOCK=infinity" > /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf
    # sed -i 's/^-Xms.*/-Xms5g/;s/^-Xmx.*/-Xmx5g/' /etc/elasticsearch/jvm.options
    # systemctl daemon-reload
    # systemctl restart elasticsearch

  .. note::
    The two references to "5g" in the above steps will only work if the Elastic
    Server was launched with the recommended instance size t2.xlarge.  If you
    chose to use t2.large instead, change the "5g" references to "3g".

Kibana
------

Kibana is a flexible and intuitive web interface for mining and visualizing the
events and archives stored in Elasticsearch. More info at `Kibana
<https://www.elastic.co/products/kibana>`_.

1. Install the Kibana package:

  .. code-block:: console

    # yum install -y kibana-|ELASTICSEARCH_LATEST|

2. Install the Wazuh plugin for Kibana:


  * Install from URL:

  .. code-block:: console

    # cd /usr/share/kibana/
    # sudo -u kibana bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-|WAZUH_LATEST|_|ELASTICSEARCH_LATEST|.zip

3. Kibana will only listen on the loopback interface (localhost) by default,
   which means that it can be only accessed from the same machine. To access
   Kibana from the any IP set the ``server.host: "0.0.0.0"`` variable, and
   set the port to be the standard port for HTTPS: ``server.port: 443``


  .. code-block:: console

    # cat >> /etc/kibana/kibana.yml << EOF

  .. code-block:: none
    :class: output

    server.host: "0.0.0.0"
    server.port: 443
    EOF


4.  Allow Kibana (which is run as a non-root process) to bind to port 443:

  .. code-block:: console

    # setcap 'CAP_NET_BIND_SERVICE=+eip' /usr/share/kibana/node/bin/node

5. Configure the credentials to access the Wazuh API:

  .. code-block:: console

    # cat >> /usr/share/kibana/plugins/wazuh/wazuh.yml << EOF

        - wazuhapi:
           url: https://172.30.0.10
           port: 55000
           user: wazuhapiuser
           password: wazuhlab
      EOF

6. Enable and start the Kibana service:

  .. code-block:: console

  	# systemctl daemon-reload
  	# systemctl enable kibana.service
  	# systemctl start kibana.service

Disable the Elastic repository
------------------------------

Now disable the Elastic repository in order to prevent a future unintended
Elastic Stack upgrade to a version that may be in conflict with the latest
stable Wazuh packages.

  .. code-block:: console

    # sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
