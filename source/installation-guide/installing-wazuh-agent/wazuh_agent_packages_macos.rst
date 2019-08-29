.. Copyright (C) 2019 Wazuh, Inc.

.. _wazuh_agent_packages_macos:

Install Wazuh agent on macOS
============================

The macOS agent can be downloaded from :doc:`packages list<../packages-list/index>`. You can install it by using the command line or following the GUI steps:

  a) Using the command line, you can choose installation or deployment:

    * Installation:

      .. code-block:: console

        # installer -pkg wazuh-agent-3.9.5-1.pkg -target /

    * Deployment:

      You can automate the agent registration and configuration using variables. It is necessary to define at least the variable ``WAZUH_MANAGER_IP``. The agent will    use this value to register and it will be the assigned manager for forwarding events.

      .. code-block:: console

        # launchctl setenv WAZUH_MANAGER_IP "10.0.0.2" && installer -pkg wazuh-agent-3.9.5-1.pkg -target /

      See the following document for additional automated deployment options :doc:`deployment variables <deployment_variables>`.

  b) Using the GUI:


     Using the GUI you can perform a simple installation, without register and configure the agent. Double click on the downloaded file and follow the wizard. If you are not sure how to respond to some of the prompts, simply use the default answers.

     .. thumbnail:: ../../images/installation/macos.png
         :align: center

By default, all agent files can be found at the following location: ``/Library/Ossec/``.

Now that the agent is installed, if you didn't use the deployment method, you will now have to register and configure the agent to communicate with the manager. For more information about this process, please visit :doc:`user manual<../../user-manual/registering/index>`.

Uninstall
---------

To uninstall the agent in macOS:

1. Stop the Wazuh agent service

    .. code-block:: console

      # /Library/Ossec/bin/ossec-control stop

2. Remove the ``/Library/Ossec/`` folder and ``ossec-init.conf`` file

  .. code-block:: console

    # /bin/rm -r /Library/Ossec
    # /bin/rm /etc/ossec-init.conf

3. Stop and unload dispatcher

  .. code-block:: console

    # /bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist

4. Remove ``launchdaemons`` and ``StartupItems``

  .. code-block:: console

    # /bin/rm -f /Library/LaunchDaemons/com.wazuh.agent.plist
    # /bin/rm -rf /Library/StartupItems/WAZUH

5. Remove User and Groups

  .. code-block:: console

    # /usr/bin/dscl . -delete "/Users/ossec"
    # /usr/bin/dscl . -delete "/Groups/ossec"

6. Remove from ``pkgutil``

  .. code-block:: console

    # /usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent
    # /usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent-etc
