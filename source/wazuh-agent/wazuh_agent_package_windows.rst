.. Copyright (C) 2020 Wazuh, Inc.

.. meta:: :description: Learn how to install the Wazuh agent on Windows

.. _wazuh_agent_package_windows:

Windows
=======

.. note:: You will need administrator privileges to perform this installation.

The first step to install the Wazuh agent on a Windows machine is to download the `Windows installer <https://packages.wazuh.com/3.x/windows/wazuh-agent-|WAZUH_LATEST|-1.msi>`_ from the :ref:`packages list<packages>`. Once this is downloaded, you can install it using the command line or following the GUI steps:

  a) Using the command line, you can choose between installation or deployment:

    * Installation:

        To install the Windows agent from the command line, run the installer using the following command (the ``/q`` argument is used for unattended installations)

      * Using CMD: ::

	  wazuh-agent-|WAZUH_LATEST|-1.msi /q

      * Using PowerShell: ::

	  .\wazuh-agent-|WAZUH_LATEST|-1.msi /q


    * Deployment:

        You can automate the agent registration and configuration using variables. It is necessary to define at least the variable ``ADDRESS`` and ``AUTHD_SERVER``. The agent will use those values to register and assign a Wazuh manager for forwarding events.

	* Using CMD: ::

            wazuh-agent-|WAZUH_LATEST|-1.msi /q WAZUH_MANAGER="10.0.0.2" WAZUH_REGISTRATION_SERVER="10.0.0.2"

	* Using PowerShell: ::

	    .\wazuh-agent-|WAZUH_LATEST|-1.msi /q WAZUH_MANAGER="10.0.0.2" WAZUH_REGISTRATION_SERVER="10.0.0.2"

    See the following document for additional automated deployment options: :ref:`deployment variables for Windows <deployment_variables_windows>`.


  b) Using the GUI:


    To install the Windows agent from the GUI, run the downloaded file and follow the steps in the installation wizard. If you are not sure how to answer to some of the prompts, simply use the default answers.

    Once installed, the agent uses a graphical user interface for configuration, opening the log file or starting and stopping the service.

        .. thumbnail:: ../images/manual/windows-agent.png
            :align: center
            :width: 320 px

    By default, all agent files will be found in: ``C:\Program Files (x86)\ossec-agent``.

    Now that the agent is installed, the next step is to register and configure it to communicate with the manager. For more information about this process, please visit the document: :ref:`user manual<register_agents>`.

Uninstall
---------

To uninstall the agent, the original MSI file will be needed to perform the unattended process::

    msiexec.exe /x wazuh-agent-|WAZUH_LATEST|-1.msi /qn
