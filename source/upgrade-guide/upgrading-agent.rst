.. Copyright (C) 2022 Wazuh, Inc.
.. meta::
  :description: Check out how to upgrade the Wazuh agent to the latest available version remotely, using the agent_upgrade tool or the Wazuh API, or locally.

.. _upgrading_wazuh_agent:

Wazuh agent
===========

The following steps show how to upgrade the Wazuh agent to the latest available version. Since Wazuh 3.x, it is possible to upgrade the Wazuh agents either remotely from the Wazuh manager or locally. Upgrading the Wazuh agents remotely is possible by using the ``agent_upgrade`` tool or the Wazuh API. More information about the process can be found in the :ref:`Remote agent upgrade<upgrading-agent>` section.

To perform the upgrade locally, follow the instructions for the operating system of the Wazuh agent:

.. tabs::

  .. group-tab:: Yum

    #. Import the GPG key:

       .. code-block:: console

        # rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

    #. Add the repository:

       .. code-block:: console

         # cat > /etc/yum.repos.d/wazuh.repo << EOF
         [wazuh]
         gpgcheck=1
         gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
         enabled=1
         name=EL-\$releasever - Wazuh
         baseurl=https://packages.wazuh.com/4.x/yum/
         protect=1
         EOF

    #. Clean the YUM cache:

       .. code-block:: console

         # yum clean all


    #. Upgrade the Wazuh agent to the latest version:

       .. code-block:: console

          # yum upgrade wazuh-agent


    #. It is recommended to disable the Wazuh repository in order to avoid undesired upgrades and compatibility issues as the Wazuh agent should always be in the same or an older version than the Wazuh manager:

        .. code-block:: console

          # sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo


  .. group-tab:: APT

    #. Install the GPG key:

       .. code-block:: console

         # curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -

    #. Add the repository:

       .. code-block:: console

         # echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list


    #. Upgrade the Wazuh agent to the latest version:

        .. code-block:: console

          # apt-get update
          # apt-get install wazuh-agent


    #. It is recommended to disable the Wazuh repository in order to avoid undesired upgrades and compatibility issues as the Wazuh agent should always be in the same or an older version than the Wazuh manager. Skip this step if the package is set to a ``hold`` state:

        .. code-block:: console

          # sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list
          # apt-get update


  .. group-tab:: ZYpp

    #. Import the GPG key:

       .. code-block:: console

         # rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

    #. Add the repository:

       .. code-block:: console

         # cat > /etc/zypp/repos.d/wazuh.repo <<\EOF
         [wazuh]
         gpgcheck=1
         gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
         enabled=1
         name=EL-$releasever - Wazuh
         baseurl=https://packages.wazuh.com/4.x/yum/
         protect=1
         EOF

    #. Refresh the repository:

       .. code-block:: console

         # zypper refresh


    #. Upgrade the Wazuh agent to the latest version:

        .. code-block:: console

          # zypper update wazuh-agent


    #. It is recommended to disable the Wazuh repository in order to avoid undesired upgrades and compatibility issues as the Wazuh agent should always be in the same or an older version than the Wazuh manager:

        .. code-block:: console

          # sed -i "s/^enabled=1/enabled=0/" /etc/zypp/repos.d/wazuh.repo


  .. group-tab:: Windows

    The Wazuh agent upgrading process for Windows systems requires to download the latest `Windows installer <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_WINDOWS|/windows/wazuh-agent-|WAZUH_CURRENT_WINDOWS|-|WAZUH_REVISION_WINDOWS|.msi>`_. There are two ways of using the installer, both of them require ``administrator rights``.

    a) Using the GUI installer. Open the installer and follow the instructions to upgrade the Wazuh agent:

        .. thumbnail:: ../images/installation/windows.png
          :title: Windows agent
          :align: left
          :width: 100%

    b) Using the command line. To upgrade the Wazuh agent from the command line, run the installer using Windows PowerShell or the command prompt. The ``/q`` argument is used for unattended installations:

      .. code-block:: none

        # .\wazuh-agent-|WAZUH_CURRENT_WINDOWS|-|WAZUH_REVISION_WINDOWS|.msi /q


  .. group-tab:: macOS

    The Wazuh agent upgrading process for macOS systems requires to download the latest `macOS installer <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_OSX|/macos/wazuh-agent-|WAZUH_CURRENT_OSX|-|WAZUH_REVISION_OSX|.pkg>`_. There are two ways of using the installer.

    a) Using the GUI will perform a simple upgrade. Double click on the downloaded file and follow the wizard. If you are not sure how to answer some of the prompts, simply use the default answers:

     .. image:: ../images/installation/macos.png
         :align: left
         :scale: 50 %


    b) Using the command line:

      .. code-block:: console

        # installer -pkg wazuh-agent-|WAZUH_CURRENT_OSX|-|WAZUH_REVISION_OSX|.pkg -target /


  .. group-tab:: AIX

    The Wazuh agent upgrading process for AIX systems requires to download the latest `AIX installer <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_AIX|/aix/wazuh-agent-|WAZUH_CURRENT_AIX|-|WAZUH_REVISION_AIX|.aix.ppc.rpm>`_ and run the following command:

    .. code-block:: console

      # rpm -U wazuh-agent-|WAZUH_CURRENT_AIX|-|WAZUH_REVISION_AIX|.aix.ppc.rpm



  .. group-tab:: Solaris 11

    The Wazuh agent upgrading process for Solaris 11 systems requires to download the latest `Solaris 11 i386 installer <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_SOLARIS11|/solaris/i386/11/wazuh-agent_v|WAZUH_CURRENT_SOLARIS11|-sol11-i386.p5p>`_ or `Solaris 11 sparc installer <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_SOLARIS11|/solaris/sparc/11/wazuh-agent_v|WAZUH_CURRENT_SOLARIS11|-sol11-sparc.p5p>`_ depending on the Solaris 11 host architecture.

    #. Stop the Wazuh agent:

        .. code-block:: console

          # /var/ossec/bin/wazuh-control stop


    #. After that, upgrade the Wazuh agent. Choose one option depending on the host architecture:

        * Solaris 11 i386:

            .. code-block:: console

              # pkg install -g wazuh-agent_v|WAZUH_CURRENT_SOLARIS11|-sol11-i386.p5p wazuh-agent

        * Solaris 11 sparc:

            .. code-block:: console

              # pkg install -g wazuh-agent_v|WAZUH_CURRENT_SOLARIS11|-sol11-sparc.p5p wazuh-agent


    #. Start the Wazuh agent:

        .. code-block:: console

          # /var/ossec/bin/wazuh-control start


  .. group-tab:: Solaris 10

    The Wazuh agent upgrading process for Solaris 10 systems requires to download the latest `Solaris 10 i386 installer <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_SOLARIS10|/solaris/i386/10/wazuh-agent_v|WAZUH_CURRENT_SOLARIS10|-sol10-i386.pkg>`_ or `Solaris 10 sparc installer <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_SOLARIS10|/solaris/sparc/10/wazuh-agent_v|WAZUH_CURRENT_SOLARIS10|-sol10-sparc.pkg>`_ depending on the Solaris 10 host architecture.

    #. Stop the Wazuh agent:

        .. code-block:: console

          # /var/ossec/bin/wazuh-control stop


    #. Backup the ``ossec.conf`` and ``client.keys`` files:

        .. code-block:: console

          # cp /var/ossec/etc/ossec.conf ~/ossec.conf.bk
          # cp /var/ossec/etc/client.keys ~/client.keys.bk


    #. Remove the Wazuh agent:

        .. code-block:: console

          # pkgrm wazuh-agent


    #. After that, install the Wazuh agent. Choose one option depending on the host architecture:

        * Solaris 10 i386:

            .. code-block:: console

              # pkgadd -d wazuh-agent_v|WAZUH_CURRENT_SOLARIS10|-sol10-i386.pkg wazuh-agent

        * Solaris 10 sparc:

            .. code-block:: console

              # pkgadd -d wazuh-agent_v|WAZUH_CURRENT_SOLARIS10|-sol10-sparc.pkg wazuh-agent


    #. Restore the ``ossec.conf`` and ``client.keys`` files:

        .. code-block:: console

          # mv ~/ossec.conf.bk /var/ossec/etc/ossec.conf
          # chown root:wazuh /var/ossec/etc/ossec.conf
          # mv ~/client.keys.bk /var/ossec/etc/client.keys
          # chown root:wazuh /var/ossec/etc/client.keys


    #. Start the wazuh-agent:

        .. code-block:: console

          # /var/ossec/bin/wazuh-control start


  .. group-tab:: HP-UX

      The Wazuh agent upgrading process for HP-UX systems requires to download the latest `HP-UX installer <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_HPUX|/hp-ux/wazuh-agent-|WAZUH_CURRENT_HPUX|-|WAZUH_REVISION_HPUX|-hpux-11v3-ia64.tar>`_.

      #. Stop the Wazuh agent:

          .. code-block:: console

            # /var/ossec/bin/wazuh-control stop


      #. Backup the ``ossec.conf`` configuration file:

          .. code-block:: console

            # cp /var/ossec/etc/ossec.conf ~/ossec.conf.bk
            # cp /var/ossec/etc/client.keys ~/client.keys.bk


      #. **Only for upgrades from version 4.2.7 or lower**:  
      
         #. Delete ossec user and group:

            .. code-block:: console

              # groupdel ossec
              # userdel ossec

         #. Create the wazuh user and group:

            .. code-block:: console

              # groupadd wazuh
              # useradd -G wazuh wazuh

      #. Deploy the Wazuh agent files:

          .. code-block:: console

            # tar -xvf wazuh-agent-|WAZUH_CURRENT_HPUX|-|WAZUH_REVISION_HPUX|-hpux-11v3-ia64.tar


      #. Restore the ``ossec.conf`` configuration file:

          .. code-block:: console

            # mv ~/ossec.conf.bk /var/ossec/etc/ossec.conf
            # chown root:wazuh /var/ossec/etc/ossec.conf
            # mv ~/client.keys.bk /var/ossec/etc/client.keys
            # chown root:wazuh /var/ossec/etc/client.keys


      #. Start the wazuh-agent:

          .. code-block:: console

            # /var/ossec/bin/wazuh-control start


Once the Wazuh agent is upgraded, if it still uses UDP, which was the default protocol for versions prior to Wazuh 4.x, it must be changed to TCP in the ``ossec.conf`` file:

.. code-block:: console
  :emphasize-lines: 6

  <ossec_config>
    <client>
      <server>
        <address>172.16.1.17</address>
        <port>1514</port>
        <protocol>udp</protocol>
      </server>
