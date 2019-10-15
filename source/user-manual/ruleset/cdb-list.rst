.. Copyright (C) 2019 Wazuh, Inc.

.. _ruleset_cdb-list:

Using CDB lists
===============

Wazuh is able to check if a field extracted during the decoding phase is in a CDB list (constant database). The main use case of this feature is to create a white/black list of users, IPs or domain names.

Creating a CDB list
-------------------

Creating the list file
^^^^^^^^^^^^^^^^^^^^^^

The list file is a plain text file where each line has the following format::

    key1:value1
    key2:value2

Each key must be unique and is terminated with a colon ``:``.

For IP addresses the dot notation is used for subnet matches:

+-------------+----------------+-------------------------------+
| key         | CIDR           | Possible matches              |
+=============+================+===============================+
| 192.168.:   | 192.168.0.0/16 | 192.168.0.0 - 192.168.255.255 |
+-------------+----------------+-------------------------------+
| 172.16.19.: | 172.16.19.0/24 | 172.16.19.0 - 172.16.19.255   |
+-------------+----------------+-------------------------------+
| 10.1.1.1:   | 10.1.1.1/32    | 10.1.1.1                      |
+-------------+----------------+-------------------------------+

Example of IP address list file::

    192.168.: Matches 192.168.0.0 - 192.168.255.255
    172.16.19.: Matches 172.16.19.0 - 172.16.19.255
    10.1.1.1: Matches 10.1.1.1

We recommend to store the lists on ``/var/ossec/etc/lists``.

.. note::
  Until version 3.11, ``ossec-makelist`` compiled the CDB list. Now, the CBD list will be compiled at the start of wazuh or running ``ossec-logtest``  

Adding the list to ossec.conf
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Each list must be defined in the ``ossec.conf`` file using the following syntax:

.. code-block:: xml

  <ossec_config>
    <ruleset>
      <list>etc/lists/list-IP</list>

.. warning::
  The ``<list>`` setting uses a relative path to the Wazuh installation folder (``/var/ossec/``) so make sure to indicate the directory accordingly.

Restart Wazuh to apply the changes:

  a. For Systemd:

  .. code-block:: console

    # systemctl restart wazuh-manager

  b. For SysV Init:

  .. code-block:: console

    # service wazuh-manager restart

Using the CDB list in the rules
-------------------------------

A rule would use the following syntax to look up a key within a CDB list.

Positive key match
^^^^^^^^^^^^^^^^^^

This example is a search for the key stored in the field attribute and will match if it **IS** present in the database:

.. code-block:: xml

     <list field="user" lookup="match_key">etc/lists/list-user</list>

The ``lookup="match_key"`` is the default and can be left out as in this example:

.. code-block:: xml

     <list field="user">etc/lists/list-user</list>

In case the field is an IP address, you must to use *address_match_key*:

.. code-block:: xml

    <list field="srcip" lookup="address_match_key">etc/lists/list-IP</list>

Negative key match
^^^^^^^^^^^^^^^^^^

This example is a search for the key stored in the field attribute and will match if it *IS NOT* present in the database:

.. code-block:: xml

    <list field="user" lookup="not_match_key">etc/lists/list-user</list>

In case the field is an IP address, you must use *not_address_match_key*:

.. code-block:: xml

    <list field="srcip" lookup="not_address_match_key">etc/lists/list-IP</list>

Key and value match
^^^^^^^^^^^^^^^^^^^

This example is a search for the key stored in the field attribute, and on a positive match the returned value of the key will be processed using the regex in the check_value attribute:

.. code-block:: xml

     <list field="user" lookup="match_key_value" check_value="^block">etc/lists/list-user</list>

In case the field is an IP address, you must use *not_address_match_key*:

.. code-block:: xml

   <list field="srcip" lookup="address_match_key_value" check_value="^reject">etc/lists/list-IP</list>


CDB lists examples
^^^^^^^^^^^^^^^^^^

.. code-block:: xml

  <rule id="110700" level="10">
    <if_group>json</if_group>
    <list field="ip" lookup="address_match_key">etc/lists/List-one</list>
    <description>IP blacklisted in LIST ONE</description>
    <group>list1,</group>
  </rule>


  <rule id="110701" level="10">
    <if_group>json</if_group>
    <list field="ip" lookup="address_match_key">etc/lists/List-two</list>
    <description>IP blacklisted in LIST TWO</description>
    <group>list2,</group>
  </rule>


  <rule id="110710" level="10">
    <if_sid>110700</if_sid>
    <list field="ip" lookup="address_match_key">etc/lists/List-two</list>
    <description>IP blacklisted in LIST ONE and LIST TWO</description>
    <group>list1,list2,</group>
  </rule>

In this example, the described rules check if an IP is in the *list-one*, in the *list-two*, or in both.
