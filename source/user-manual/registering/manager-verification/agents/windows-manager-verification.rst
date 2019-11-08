.. Copyright (C) 2019 Wazuh, Inc.

.. _windows-manager-verification:

Windows agents
==============

To register the Windows Agent, you need to start a CMD or a Powershell as **Administrator**. The installation directory of the Wazuh agent in Windows host depends on the architecture of the host.

	- ``C:\Program Files (x86)\ossec-agent`` for ``x86_64`` hosts.
	- ``C:\Program Files\ossec-agent`` for ``x64`` hosts.

This guide suppose that the Wazuh agent is installed in a ``x86_64`` host, so the installation path will be: ``C:\Program Files (x86)\ossec-agent``.

After that, you can register the agent using ``agent-auth.exe``:

1. Copy the CA (**.pem file**) to the ``C:\Program Files (x86)\ossec-agent`` folder and run the ``agent-auth`` program:

  .. code-block:: console

    # cp rootCA.pem C:\Program Files (x86)\ossec-agent
    # C:\Program Files (x86)\ossec-agent\agent-auth.exe -m 192.168.1.2 -v C:\Program Files (x86)\ossec-agent\rootCA.pem

  .. note:: Note that this method must include the -v option that indicates the location of the CA. If this option is not included, a warning message will be displayed and the connection will be established without verifying the manager.

2. Edit the Wazuh agent configuration to add the Wazuh server IP address.

  In the file ``C:\Program Files (x86)\ossec-agent\ossec.conf``, in the ``<client><server>`` section, change the *MANAGER_IP* value to the Wazuh server address:

  .. code-block:: xml

    <client>
      <server>
        <address>MANAGER_IP</address>
        ...
      </server>
    </client>

3. Start the agent.

	a) Using Powershell with administrator access:

		.. code-block:: console

			# Restart-Service -Name wazuh

	b) Using Windows cmd with administrator access:

		.. code-block:: console

			# net stop wazuh
			# net start wazuh

