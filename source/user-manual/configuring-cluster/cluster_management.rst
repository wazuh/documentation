.. Copyright (C) 2019 Wazuh, Inc.

Cluster management
===================

The **cluster_control** tool allows you to obtain real-time information about the cluster health, connected nodes and the agents reporting to the cluster. This information can also be obtained using the :doc:`API requests <../api/reference>`.

For example, the following snippet shows the connected nodes in the cluster:

.. code-block:: console

    # /var/ossec/bin/cluster_control -l
    NAME      TYPE    VERSION  ADDRESS
    worker-1  worker  3.10.2    172.17.0.101
    worker-2  worker  3.10.2    172.17.0.102
    master    master  3.10.2    172.17.0.100

This information can also be obtained using the Restful API:

.. code-block:: console

    # curl -u foo:bar -X GET "http://localhost:55000/cluster/nodes?pretty"
    {
       "error": 0,
       "data": {
          "totalItems": 3,
          "items": [
             {
                "ip": "192.168.56.103",
                "version": "3.10.2",
                "type": "worker",
                "name": "node02"
             },
             {
                "ip": "192.168.56.105",
                "version": "3.10.2",
                "type": "worker",
                "name": "node03"
             },
             {
                "ip": "192.168.56.101",
                "version": "3.10.2",
                "type": "master",
                "name": "node01"
             }
          ]
       }
    }

If you want to see more examples and check all its options, refer to :doc:`the cluster_control manual <../reference/tools/cluster_control>` or the :doc:`API requests <../api/reference>`.


Upgrading from older versions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you already have a cluster installation from a **version older or equal to 3.2.2**, you should do some changes in your cluster configuration:

    * Remove ``<interval>`` section.
    * Remove worker nodes from ``<nodes>`` section. Only the master node is allowed.

The cluster will work with an old configuration but it is recommended to update it.
