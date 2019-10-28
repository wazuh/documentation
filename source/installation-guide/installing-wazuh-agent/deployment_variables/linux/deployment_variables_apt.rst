.. Copyright (C) 2019 Wazuh, Inc.

.. _deployment_variables_apt:

Deployment variables for Linux using apt repository
===================================================

For an agent to be fully deployed and connected to the Wazuh server it needs to be installed, registered and configured. To make the process simple, the installers can use variables that allow the configuration provisioning.

Below you can find a table describing the variables used by Wazuh installers, and a few examples on how to use them.


+----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Option                           | Description                                                                                                                                                                                                            |
+==================================+========================================================================================================================================================================================================================+
|   WAZUH_MANAGER                  |  Specifies the manager IP address or hostname. In case you want to specify multiple managers, you can add them separated by commas. See `address <../../../user-manual/reference/ossec-conf/client.html#address>`_.    |
+----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|   WAZUH_MANAGER_PORT             |  Specifies the manager’s connection port. See `server-port <../../../user-manual/reference/ossec-conf/client.html#server-port>`_.                                                                                      |
+----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|   WAZUH_PROTOCOL                 |  Sets the communication protocol between the manager and the agent. Accepts UDP and TCP. Default is UDP. See `server-protocol <../../../user-manual/reference/ossec-conf/client.html#server-protocol>`_.               |
+----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|   WAZUH_REGISTRATION_SERVER      |  Specifies the Wazuh registration server, used for the agent registration. See `agent-auth options <../../../user-manual/reference/tools/agent-auth.html>`_.                                                           |
+----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|   WAZUH_REGISTRATION_PORT        |  Specifies the port used by the Wazuh registration server. See `agent-auth options <../../../user-manual/reference/tools/agent-auth.html>`_.                                                                           |
+----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|   WAZUH_REGISTRATION_PASSWORD    |  Sets the Wazuh registration server. See `agent-auth options <../../../user-manual/reference/tools/agent-auth.html>`_.                                                                                                 |
+----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|   WAZUH_KEEP_ALIVE_INTERVAL      |  Sets the time between agent checks for manager connection. See `notify-time <../../../user-manual/reference/ossec-conf/client.html#notify-time>`_.                                                                    |
+----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|   WAZUH_TIME_RECONNECT           |  Sets the time interval for the agent to reconnect with the Wazuh manager when connectivity is lost. See `time-reconnect <../../../user-manual/reference/ossec-conf/client.html#time-reconnect>`_.                     |
+----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|   WAZUH_REGISTRATION_CA          |  Host SSL validation need of Certificate of Authority. This option specifies the CA path. See `agent-auth options <../../../user-manual/reference/tools/agent-auth.html>`_.                                            |
+----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|   WAZUH_REGISTRATION_CERTIFICATE |  The SSL agent verification needs a CA signed certificate and the respective key. This option specifies the certificate path. See `agent-auth options <../../../user-manual/reference/tools/agent-auth.html>`_.        |
+----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|   WAZUH_REGISTRATION_KEY         |  Specifies the key path completing the required variables with WAZUH_REGISTRATION_CERTIFICATE for the SSL agent verification process. See `agent-auth options <../../../user-manual/reference/tools/agent-auth.html>`_.|
+----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|   WAZUH_AGENT_NAME               |  Designates the agent's name. By default it will be the computer name. See `agent-auth options <../../../user-manual/reference/tools/agent-auth.html>`_.                                                               |
+----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|   WAZUH_AGENT_GROUP              |  Assigns the agent to one or more existing groups (separated by commas). See `agent-auth options <../../../user-manual/reference/tools/agent-auth.html>`_.                                                             |
+----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

Examples:

* Registration with password:

.. code-block:: console

     # WAZUH_MANAGER="10.0.0.2" WAZUH_REGISTRATION_PASSWORD="TopSecret" \
          WAZUH_AGENT_NAME="aix-agent" apt-get install wazuh-agent

* Registration with password and assigning a group:

.. code-block:: console

     # WAZUH_MANAGER="10.0.0.2" WAZUH_REGISTRATION_SERVER="10.0.0.2" WAZUH_REGISTRATION_PASSWORD="TopSecret" \
          WAZUH_AGENT_GROUP="my-group" apt-get install wazuh-agent

* Registration with relative path to CA. It will be searched at your Wazuh installation folder:

.. code-block:: console

     # WAZUH_MANAGER="10.0.0.2" WAZUH_REGISTRATION_SERVER="10.0.0.2" WAZUH_AGENT_NAME="aix-agent" \
          WAZUH_REGISTRATION_CA="rootCA.pem" apt-get install wazuh-agent

* Registration with protocol:

.. code-block:: console

     # WAZUH_MANAGER="10.0.0.2" WAZUH_REGISTRATION_SERVER="10.0.0.2" WAZUH_AGENT_NAME="aix-agent" \
          WAZUH_PROTOCOL="tcp" apt-get install wazuh-agent

* Registration and adding multiple addresses:

.. code-block:: console

     # WAZUH_MANAGER="10.0.0.2,10.0.0.3" WAZUH_REGISTRATION_SERVER="10.0.0.2" \
          WAZUH_AGENT_NAME="aix-agent" apt-get install wazuh-agent

* Absolute paths to CA, certificate or key that contain spaces can be written as shown below:

.. code-block:: console

     # WAZUH_MANAGER "10.0.0.2" WAZUH_REGISTRATION_SERVER "10.0.0.2" WAZUH_REGISTRATION_KEY "/var/ossec/etc/sslagent.key" \
          WAZUH_REGISTRATION_CERTIFICATE "/var/ossec/etc/sslagent.cert" apt-get install wazuh-agent

.. note:: To verify agents identity with the registration server, it's necessary to use both KEY and PEM options. See the :ref:`agent-verification-with-host-validation` section.
