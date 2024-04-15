.. Copyright (C) 2015, Wazuh, Inc.

.. meta::
  :description: Learn more about how to register Wazuh agents on Linux, Windows, or macOS X in this section of our documentation.
  
.. _macos-endpoint:


macOS endpoint
==============

The following steps serve as a guide on how to configure a macOS endpoint agent for automatic enrollment via the agent configuration method:

#. Launch the terminal as a root user, edit the Wazuh agent configuration file ``/Library/Ossec/etc/ossec.conf``, and make the following changes:
    
   #. Include the Wazuh manager IP address or DNS name in the ``<client><server><address>`` section:
      

      .. code-block:: xml
          :emphasize-lines: 3            

            <client>
              <server>
                <address>MANAGER_IP</address>
                ...
              </server>
            </client>
      
      
      This will allow the agent to connect to the Wazuh manager and automatically request a key.
      
   #. (Optional) Add enrollment parameters in the ``<client><enrollment>`` section. 
      
      .. code-block:: xml
          :emphasize-lines: 4, 5

            <client>
                ...
                <enrollment>
                    <agent_name>EXAMPLE_NAME</agent_name>
                    <groups>GROUP1,GROUP2,GROUP3</groups>
                    ...
                </enrollment>
            </client>
      
      These agent enrollment parameters are optional, and they provide the agent with specific information that should be used during enrollment. Some common enrollment parameters are below:
   
      - ``<agent_name>EXAMPLE_NAME</agent_name>``: This specifies the name the endpoint should be enrolled as. When this is not specified, it defaults to the endpoint hostname.
      
      - ``<groups>GROUP1,GROUP2,GROUP3</groups>``: This specifies the group(s) in which the agent should be added. An agent group is a collection of agents that would share the same configuration. This allows the manager to push configuration settings to a set of agents that belong to the same group. The agent enrollment will fail if a non-existent group is specified. Therefore, it is necessary to create the desired group on the manager before using the group parameter. Additional information on agent groups can be found :ref:`here <grouping-agents>`.
   
      More optional enrollment parameters and their usage are provided :ref:`here <enrollment>`.


#. Restart the agent to make the changes effective.
  
   .. code-block:: console

     # /Library/Ossec/bin/wazuh-control restart


#. Select the **Server management** > **Endpoints Summary** module to check for the newly enrolled agent and its connection status in the Wazuh dashboard to confirm that enrollment was successful.
