.. Copyright (C) 2019 Wazuh, Inc.

.. _create-custom-wpk-manually:

Manual custom WPK packages creation
====================================

WPK packages will generally contain the complete agent code, however, this is not required.

A WPK package must contain an installation program in binary form or a script in any language supported by the agent (Bash, Python, etc). Linux WPK packages must contain a Bash script named ``upgrade.sh`` for UNIX or ``upgrade.bat`` for Windows. This program must:

 * Fork itself, as the parent, will return 0 immediately.
 * Restart the agent.
 * Write a file called upgrade_result containing a status number (0 means OK) before exiting.

Requirements
^^^^^^^^^^^^^

 * Python 2.7 or 3.5+
 * The Python ``cryptography`` package. This may be obtained using the following command:

    .. code-block:: console

            pip install cryptography

Linux WPK
^^^^^^^^^^^

Install development tools and compilers. In Linux this can easily be done using your distribution's package manager:

 a) For RPM-based distributions:

    .. code-block:: console

            # yum install make gcc policycoreutils-python automake autoconf libtool unzip

 b) For Debian-based distributions:

    .. code-block:: console

            # apt-get install make gcc libc6-dev curl policycoreutils automake autoconf libtool unzip

Download and extract the latest version:

    .. code-block:: console

            # curl -Ls https://github.com/wazuh/wazuh/archive/v3.10.0.tar.gz | tar zx

Modify the ``wazuh-3.10.0/etc/preloaded-vars.conf`` file that was downloaded to deploy an :ref:`unattended update <unattended-installation>` in the agent by uncommenting the following lines:

    .. code-block:: console

            USER_LANGUAGE="en"
            USER_NO_STOP="y"
            USER_UPDATE="y"

Compile the project from the ``src`` folder:

    .. code-block:: console

            # cd wazuh-3.10.0/src
            # make deps
            # make TARGET=agent

Delete the files that are no longer needed, this step can be skipped but the size of the WPK will be considerably larger:

    .. code-block:: console

            rm -rf doc wodles/oscap/content/* gen_ossec.sh add_localfiles.sh Jenkinsfile*
            rm -rf src/{addagent,analysisd,client-agent,config,error_messages,external/*,headers,logcollector,monitord,os_auth,os_crypto,os_csyslogd,os_dbdos_execd}
            rm -rf src/{os_integrator,os_maild,os_netos_regex,os_xml,os_zlib,remoted,reportd,shared,syscheckd,tests,update,wazuh_db,wazuh_modules}
            rm -rf src/win32
            rm -rf src/*.a
            rm -rf etc/{decoders,lists,rules}
            find etc/templates/* -maxdepth 0 -not -name "en" | xargs rm -rf

Install the root CA if you want to overwrite the root CA with the file you created previously:

    .. code-block:: console

            # cd ../
            # cp path/to/wpk_root.pem etc/wpk_root.pem

Compile the WPK package using your SSL certificate and key:

    .. code-block:: console

            # contrib/agent-upgrade/wpkpack.py output/myagent.wpk path/to/wpkcert.pem path/to/wpkcert.key *

In this example, the Wazuh project's root directory contains the proper ``upgrade.sh`` file.

Windows WPK
^^^^^^^^^^^^

Install development tools and compilers. In Linux this can easily be done using your distribution's package manager:

 For RPM-based distributions:

    .. code-block:: console

            # yum install make gcc policycoreutils-python automake autoconf libtool unzip

 For Debian-based distributions:

    .. code-block:: console

            # apt-get install make gcc libc6-dev curl policycoreutils automake autoconf libtool unzip

Download and extract the latest version of wazuh sources:

    .. code-block:: console

            # curl -Ls https://github.com/wazuh/wazuh/archive/v3.10.0.tar.gz | tar zx

Download the latest version of the wazuh MSI package:

    .. code-block:: console

            # curl -Ls https://packages.wazuh.com/3.x/windows/wazuh-agent-3.10.0-1.msi --output wazuh-agent-3.10.0-1.msi

Install the root CA if you want to overwrite the root CA with the file you created previously:

    .. code-block:: console

            # cd ../
            # cp path/to/wpk_root.pem etc/wpk_root.pem

Compile the WPK package using the MSI package and, your SSL certificate and key:

    .. code-block:: console

            # contrib/agent-upgrade/wpkpack.py output/myagent.wpk path/to/wpkcert.pem path/to/wpkcert.key path/to/wazuhagent.msi path/to/upgrade.bat path/to/do_upgrade.ps1

Definitions:
    - ``output/myagent.wpk`` is the name of the output WPK package.
    - ``path/to/wpkcert.pem`` is the path to your SSL certificate.
    - ``path/to/wpkcert.key`` is the path to your SSL certificate's key.
    - ``path/to/upgrade.bat`` is the path to the upgrade.bat file you can find an example at src/win32 within the wazuh repository or write your own.
    - ``path/to/do_upgrade.ps1`` is the path to the do_upgrade.ps1 file you can find an example at src/win32 within the wazuh repository or write your own.
    - ``path/to/wazuhagent.msi`` is the path to the MSI you have downloaded in step 3.
    - ``\*`` is the file (or the files) to be included into the WPK package. In this case, all the contents will be added.

.. note::
 These are only examples. If you want to distribute a WPK package using these methods, it's important to begin with an empty directory.

