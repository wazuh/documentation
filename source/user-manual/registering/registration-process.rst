.. Copyright (C) 2019 Wazuh, Inc.

.. _registration-process:

The registration process
=========================

Every Wazuh agent sends data to the Wazuh manager via a secure way called OSSEC message protocol. This protocol encrypts messages using a pre-shared key. In a fresh install, if you didn't register and configure your agent during the installation time, the agent can't communicate with the manager due to the lack of this pre-shared key.

The registration process consists of a mechanism to create a trusted relationship between the Manager and an Agent. This process could be done in a Manager itself or with a registration service. This service runs on the Manager, where an Agent could request a pre-shared key using some credentials. The Manager will reply with the key and store the new Agent in a local database.

Another approach is using the Wazuh API, this is just a wrapper for local registration on Wazuh manager.

.. _agent-keys-registration:

Agent keys
-----------

The manager uses the file ``/var/ossec/etc/client.keys`` to store the registration record of each agent, which includes ID, name, IP, and key. Example::

    001 Server1 any e20e0394dca71bacdea57d4ca25d203f836eca12eeca1ec150c2e5f4309a653a
    002 ServerProd 192.246.247.247 b0c5548beda537daddb4da698424d0856c3d4e760eaced803d58c07ad1a95f4c
    003 DBServer 192.168.0.1/24 8ec4843da9e61647d1ec3facab542acc26bd0e08ffc010086bb3a6fc22f6f65b

The agents also have the file ``/var/ossec/etc/client.keys`` containing only their own registration record. Example for ``Server1`` agent::

    001 Server1 any e20e0394dca71bacdea57d4ca25d203f836eca12eeca1ec150c2e5f4309a653a

**Basic data for registering an agent**

In order to register an agent, it is necessary to provide the name and the IP of the agent.

There are several ways to set the agent IP:

 - **Any IP**: Allow the agent to connect from any IP address. Example: ``Server1`` has ``any`` IP.
 - **Fixed IP**: Allow the agent to connect only from the specified IP. Example: ``ServerProd`` has the IP ``192.246.247.247``.
 - **Range IP**: Allow the agent to connect from the specified range of IPs. Example: ``DBServer`` has the IP range ``192.168.0.1/24``.

Some registration methods automatically detect the IP of the agent during the registration process.

Registration methods
----------------------

Here you can find different methods to register the Wazuh agents:

+----------------+---------------------------------------------------------------+
| Type           | Method                                                        |
+================+===============================================================+
| Manual method  | :ref:`using-command-line`                                     |
+----------------+---------------------------------------------------------------+
| Semi automatic | :ref:`restful-api-register`                                   |
+----------------+---------------------------------------------------------------+
|                | :ref:`simple-registration-service`                            |
|                +---------------------------------------------------------------+
| Automatic      | :ref:`password-authorization-registration-service`            |
|                +---------------------------------------------------------------+
|                | :ref:`manager-verification-registration`                      |
|                +---------------------------------------------------------------+
|                | :ref:`agent-verification-with-host-validation`                |
|                +---------------------------------------------------------------+
|                | :ref:`agent-verification-without-host-validation`             |
+----------------+---------------------------------------------------------------+

.. note::

	If you're running Wazuh in cluster mode, refer to the :ref:`Configuring a cluster section <load_balancer>` to get more details about the registration process in the cluster.
