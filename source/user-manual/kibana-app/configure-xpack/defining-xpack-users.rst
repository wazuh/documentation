.. Copyright (C) 2018 Wazuh, Inc.

.. _defining_xpack_users:

Defining X-Pack users
=====================

Using the X-Pack `Security plugin <https://www.elastic.co/products/stack/security>`_ and its RBAC features, we can define user roles to determine who can use the app or see specific index patterns. Below you'll find a summary table of what we need to configure for the app to work properly. The following sections describe briefly what each role can do.

+------------------------------------------------------------------------+-------------------------------------------------------------+
| User                                                                   | Roles                                                       |
+========================================================================+=============================================================+
| Kibana system user                                                     | **wazuh-admin**, **kibana_system**                          |
+------------------------------------------------------------------------+-------------------------------------------------------------+
| Wazuh administrator user                                               | **wazuh-basic**, **wazuh-api-admin**                        |
+------------------------------------------------------------------------+-------------------------------------------------------------+
| Wazuh standard user #1, Wazuh standard user #2...                      | **wazuh-basic**                                             |
+------------------------------------------------------------------------+-------------------------------------------------------------+

Kibana system user
------------------

This user is based on the pre-built role named ``kibana_system``, but it must be able to fetch and write data to Wazuh indices too.

To do so, we'll define another role called ``wazuh-admin`` to handle data related to Wazuh.

1. Defining the ``wazuh-admin`` role:

    a) At cluster level, it will need the following privileges:

    +------------------------------------------------------------------------+-------------------------------------------------------------+
    |Cluster privileges                                                      | Check                                                       |
    +========================================================================+=============================================================+
    |manage                                                                  | **Yes**                                                     |
    +------------------------------------------------------------------------+-------------------------------------------------------------+
    |manage_index_templates                                                  | **Yes**                                                     |
    +------------------------------------------------------------------------+-------------------------------------------------------------+

    b) At index level, it will need the following privileges:

    +------------------------------------------------------------------------+-------------------------------------------------------------+
    |Indices                                                                 | Privileges                                                  |
    +========================================================================+=============================================================+
    |.old-wazuh                                                              | **all**                                                     |
    +------------------------------------------------------------------------+-------------------------------------------------------------+
    |.wazuh                                                                  | **all**                                                     |
    +------------------------------------------------------------------------+-------------------------------------------------------------+
    |.wazuh-version                                                          | **all**                                                     |
    +------------------------------------------------------------------------+-------------------------------------------------------------+
    |wazuh-*                                                                 | **all**                                                     |
    +------------------------------------------------------------------------+-------------------------------------------------------------+

Wazuh administrator user
------------------------

This user will be able to login into Kibana UI, navigate through the Wazuh app and also add/delete Wazuh API entries.

.. note::

    This user will use two roles: ``wazuh-basic`` and ``wazuh-api-admin``. The ``wazuh-admin`` role will be used to handle data related to Wazuh and the ``wazuh-api-admin`` role will be used to add/delete Wazuh API entries.

1. Defining the ``wazuh-basic`` role:

    a) At cluster level, it won't need any privileges. At index level, it will need the following privileges:

    +------------------------------------------------------------------------+-------------------------------------------------------------+
    |Indices                                                                 | Privileges                                                  |
    +========================================================================+=============================================================+
    |.kibana                                                                 | **read**                                                    |
    +------------------------------------------------------------------------+-------------------------------------------------------------+
    |.wazuh                                                                  | **read**                                                    |
    +------------------------------------------------------------------------+-------------------------------------------------------------+
    |.wazuh-version                                                          | **read**                                                    |
    +------------------------------------------------------------------------+-------------------------------------------------------------+
    |wazuh-alerts-3.x-*                                                      | **read**                                                    |
    +------------------------------------------------------------------------+-------------------------------------------------------------+
    |wazuh-monitoring-3.x-*                                                  | **read**                                                    |
    +------------------------------------------------------------------------+-------------------------------------------------------------+

2. Defining the ``wazuh-api-admin`` role:

    a) At cluster level, it won't need any privileges. At index level, it will need the following privileges:

    +------------------------------------------------------------------------+-------------------------------------------------------------+
    |Indices                                                                 | Privileges                                                  |
    +========================================================================+=============================================================+
    |.wazuh                                                                  | **all**                                                     |
    +------------------------------------------------------------------------+-------------------------------------------------------------+

Wazuh standard user
-------------------

We need one or more users who will be able to login into Kibana UI with read only privileges. This user only needs to use the wazuh-basic role.
