.. Copyright (C) 2019 Wazuh, Inc.

.. _wazuh_agent_macos:

Install Wazuh agent on Mac OS X
===============================

The Mac OS X agent can be downloaded from :doc:`packages list<../packages-list/index>`. You can install it by using the command line or following the GUI steps:

  a) The command line::

        installer -pkg wazuh-agent-3.8.2-1.pkg -target /

  b) The GUI:

     Double click on the downloaded file and follow the wizard. If you are not sure how to respond to some of the prompts, simply use the default answers.

     .. thumbnail:: ../../images/installation/macos.png
         :align: center

By default, all agent files can be found at the following location: ``/Library/Ossec/``.

.. note:: Now that the agent is installed, the next step is to register and configure it to communicate with the manager. For more information about this process, please visit the :doc:`user manual<../../user-manual/registering/index>`.
