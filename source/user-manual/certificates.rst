.. Copyright (C) 2015, Wazuh, Inc.

.. meta::
  :description: Learn more about certificates deployment in this section of the Wazuh user manual.

.. _user_manual_certificates:

Certificates deployment
=======================

In the :ref:`installation guide <installation_guide>`, the Wazuh certs tool has been used to create certificates, but any other certificates creation method, for example using `OpenSSL <https://www.openssl.org/>`_, can be used. 

The Wazuh certs tool can be downloaded here: `wazuh-certs-tool.sh <https://packages.wazuh.com/|WAZUH_CURRENT_MINOR|/wazuh-certs-tool.sh>`_.

There are three kinds of certificates needed for the installation:

- ``root-ca``: This certificate is the one in charge of signing the rest of the certificates.

- ``node``: The node certificates are the ones needed for every Wazuh indexer node. They must include the node IP address.

- ``admin``: The admin certificate is a client certificate with special privileges needed for management and security-related tasks.

These certificates are created with the following additional information:

- ``C``: US

- ``L``: California

- ``O``: Wazuh

- ``OU``: Wazuh

- ``CN``: Name of the node


To create the certificates, edit the ``config.yml`` file and replace the node names and IP values with the corresponding names and IP addresses. The ``<node-ip>`` can be either an IP address or a DNS name. The ``config.yml`` template can be found here: `config.yml <https://packages.wazuh.com/|WAZUH_CURRENT_MINOR|/config.yml>`_. 

    .. code-block:: yaml

       nodes:
         # Wazuh indexer nodes
         indexer:
           - name: node-1
             ip: <indexer-node-ip>
           # - name: node-2
           #   ip: <indexer-node-ip>
           # - name: node-3
           #   ip: <indexer-node-ip>
       
         # Wazuh server nodes
         # Use node_type only with more than one Wazuh manager
         server:
           - name: wazuh-1
             ip: <wazuh-manager-ip>
           # node_type: master
           # - name: wazuh-2
           #   ip: <wazuh-manager-ip>
           # node_type: worker
       
         # Wazuh dashboard nodes
         dashboard:
           - name: dashboard
             ip: <dashboard-node-ip>

After configuring the ``config.yml``, run the script with option ``-A`` to create all the certificates. 

    .. code-block:: console

        # bash wazuh-certs-tool.sh -A

After running the script, the directory ``wazuh-certificates`` will be created and will have the following content:

    .. code-block:: none

        wazuh-certificates/
        ├── admin-key.pem
        ├── admin.pem
        ├── dashboard-key.pem
        ├── dashboard.pem
        ├── indexer-key.pem
        ├── indexer.pem
        ├── root-ca.key
        ├── root-ca.pem
        ├── server-key.pem
        └── server.pem

Additionally, this script allows the use of a pre-existent rootCA certificate. To create all the certificates using a pre-existent rootCA certificate, use option ``-A`` and indicate the ``root-ca`` certificate and key as follows:

    .. code-block:: console

        # bash wazuh-certs-tool.sh -A /path/to/root-ca.pem /path/to/root-ca.key

After running the script, the directory ``wazuh-certificates`` will be created and will have the following content:

    .. code-block:: none

        wazuh-certificates/
        ├── admin-key.pem
        ├── admin.pem
        ├── dashboard-key.pem
        ├── dashboard.pem
        ├── indexer-key.pem
        ├── indexer.pem
        ├── server-key.pem
        └── server.pem
        
        
To update the certificates for each module and to restart:

    .. code-block:: none
    
      # Use indexer name from config.yml
      NODE_NAME=<indexer>

      # Backup
      mv /etc/wazuh-indexer/certs/wazuh-indexer.pem /etc/wazuh-indexer/certs/wazuh-indexer.pem.old
      mv /etc/wazuh-indexer/certs/wazuh-indexer-key.pem /etc/wazuh-indexer/certs/wazuh-indexer-key.pem.old
      mv /etc/wazuh-indexer/certs/admin.pem /etc/wazuh-indexer/certs/admin.pem.old
      mv /etc/wazuh-indexer/certs/admin-key.pem /etc/wazuh-indexer/certs/admin-key.pem.old
      mv /etc/wazuh-indexer/certs/root-ca.pem /etc/wazuh-indexer/certs/root-ca.pem.old


      # Copy new created cert to destination
      cp -n wazuh-certificates/$NODE_NAME.pem /etc/wazuh-indexer/certs/wazuh-indexer.pem
      cp -n wazuh-certificates/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/wazuh-indexer-key.pem
      cp wazuh-certificates/admin-key.pem /etc/wazuh-indexer/certs/
      cp wazuh-certificates/admin.pem /etc/wazuh-indexer/certs/
      cp wazuh-certificates/root-ca.pem /etc/wazuh-indexer/certs/

      # Set Permissions
      chmod 500 /etc/wazuh-indexer/certs
      chmod 400 /etc/wazuh-indexer/certs/*
      chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs


      # Restart
      systemctl restart wazuh-indexer

      # Use server name from config.yml
      NODE_NAME=<server>

      # Backup 
      mv /etc/filebeat/certs/wazuh-server.pem /etc/filebeat/certs/wazuh-server.pem.old
      mv /etc/filebeat/certs/wazuh-server-key.pem /etc/filebeat/certs/wazuh-server-key.pem.old
      mv /etc/filebeat/certs/root-ca.pem /etc/filebeat/certs/root-ca.pem.old

      cp -n wazuh-certificates/$NODE_NAME.pem /etc/filebeat/certs/wazuh-server.pem
      cp -n wazuh-certificates/$NODE_NAME-key.pem /etc/filebeat/certs/wazuh-server-key.pem
      cp wazuh-certificates/root-ca.pem /etc/filebeat/certs/
      chmod 500 /etc/filebeat/certs
      chmod 400 /etc/filebeat/certs/*
      chown -R root:root /etc/filebeat/certs

      # Restart
      systemctl restart filebeat



      # Use filebeat name from config.yml
      NODE_NAME=<filebeat>

      #Backup
      mv /etc/wazuh-dashboard/certs/wazuh-dashboard.pem /etc/wazuh-dashboard/certs/wazuh-dashboard.pem.old
      mv /etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem /etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem.old
      mv /etc/wazuh-dashboard/certs/root-ca.pem /etc/wazuh-dashboard/certs/root-ca.pem.old

      cp -n wazuh-certificates/$NODE_NAME.pem /etc/wazuh-dashboard/certs/wazuh-dashboard.pem
      cp -n wazuh-certificates/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem
      cp wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/
      chmod 500 /etc/wazuh-dashboard/certs
      chmod 400 /etc/wazuh-dashboard/certs/*
      chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

      # Restart
      systemctl restart wazuh-dashboard

