.. Copyright (C) 2019 Wazuh, Inc.

.. _wazuh_agent_sources_suse11:

SUSE 11 from sources
====================

This guide describes how to install the Wazuh agent from source code for SUSE 11. For other operating systems or Linux distributions, please check the list: :ref:`Install Wazuh agent <installation_agents>`.

.. note:: All the commands described below need to be executed with root user privileges.

Installing Wazuh agent
----------------------

.. note:: All the commands described below need to be executed with root user privileges. Since Wazuh 3.5 it is necessary to have internet connection when following this process.

1. Install development tools and compilers. In Linux this can easily be done using your distribution's package manager:

    .. code-block:: console

      # zypper install make gcc policycoreutils automake autoconf libtool

    .. note:: It is possible that some of the tools are not found in the package manager, so you can add the following official repository:

        .. code-block:: console

            # zypper addrepo http://download.opensuse.org/distribution/11.4/repo/oss/ oss

2. Download and extract the latest version:

    .. code-block:: console

      # curl -Ls https://github.com/wazuh/wazuh/archive/v3.11.3.tar.gz | tar zx

    .. note:: In the case of not being able to download in this way, you can send this file through the scp utility.

3. Run the ``install.sh`` script. This will run a wizard that will guide you through the installation process using the Wazuh sources:

    .. code-block:: console

      # cd wazuh-*
      # ./install.sh

   If you have previously compiled for another platform, you must clean the build using the Makefile in ``src``:

      .. code-block:: console

        # cd wazuh-*
        # make -C src clean
        # make -C src clean-deps

   .. note::
     During the installation, users can decide the installation path. Execute the ``./install.sh`` and select the language, set the installation mode to ``agent``, then set the installation path (``Choose where to install Wazuh [/var/ossec]``). The default path of installation is ``/var/ossec``. A commonly used custom path might be ``/opt``. When choosing a different path than the default, if the directory already exist the installer will ask if delete the directory or if installing Wazuh inside. You can also run an :ref:`unattended installation <unattended-installation>`.

4. The script will ask about what kind of installation you want. Type ``agent`` in order to install a Wazuh agent:

 .. code-block:: none

    1- What kind of installation do you want (manager, agent, local, hybrid or help)? agent

Now that the agent is installed, the next step is to register and configure it to communicate with the manager. For more information about this process, please visit the document: :ref:`user manual<register_agents>`.
