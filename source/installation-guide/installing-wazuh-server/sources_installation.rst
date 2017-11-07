.. _sources_installation:

Install Wazuh server from sources
=================================

This guide describes how to install the manager and API from source code. In addition, for distributed architectures, you will find some guidance on how to install Filebeat.

.. note:: Many of the commands described below need to be executed with root user privileges.

Installing Wazuh manager
------------------------

1. Install development tools and compilers. In Linux this can easily be done using your distribution's package manager:

  a) For RPM-based distributions:

    .. code-block:: bash

      $ sudo yum install make gcc git

      # If you want to use Auth, also install:
      $ sudo yum install openssl-devel

  b) For Debian-based distributions:

    .. code-block:: bash

      $ sudo apt-get install gcc make git libc6-dev

      # If you want to use Auth, also install:
      $ sudo apt-get install libssl-dev

2. Download and extract the latest version:

  .. code-block:: bash

    $ curl -Ls https://github.com/wazuh/wazuh/archive/v2.1.0.tar.gz | tar zx

3. Run the ``install.sh`` script, this will display a wizard that will guide you through the installation process using the Wazuh sources:

  .. code-block:: bash

    $ cd wazuh-*
    $ ./install.sh


4. The script will ask about what kind of installation you want. Type ``server`` to install Wazuh Manager:

  .. code-block:: bash

    1- What kind of installation do you want (server, agent, local, hybrid or help)? server

5. Start the services using this command:

  .. code-block:: bash

    $ /var/ossec/bin/ossec-control start

Installing Wazuh API
--------------------

1. NodeJS >= 4.6.1 is required in order to run the Wazuh API. If you do not have NodeJS installed or your version is older than 4.6.1, we recommend you add the official repository as this has more recent versions.

  a) For RPM-based distributions:

    .. code-block:: bash

      $ curl --silent --location https://rpm.nodesource.com/setup_6.x | bash -
      $ yum -y install nodejs

  b) For Debian-based distributions:

    .. code-block:: bash

      $ curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash -
      $ apt-get install -y nodejs

  .. note::
	`Official guide to install NodeJS <https://nodejs.org/en/download/package-manager/>`_.

2. Download and execute the installation script:

  .. code-block:: bash

      $ curl -s -o install_api.sh https://raw.githubusercontent.com/wazuh/wazuh-api/v2.1.0/install_api.sh && bash ./install_api.sh download

3. Python >= 2.7 is required in order to run the API. It is installed by default or included in the official repositories of most Linux distributions. It is possible to set a custom Python path for the API to use, in ``/var/ossec/api/configuration/config.js``:

  .. code-block:: javascript

    config.python = [
        // Default installation
        {
            bin: "python",
            lib: ""
        },
        // Package 'python27' for CentOS 6
        {
            bin: "/opt/rh/python27/root/usr/bin/python",
            lib: "/opt/rh/python27/root/usr/lib64"
        }
    ];

  CentOS 6 and Red Hat 6 come with Python 2.6, you can install Python 2.7 in parallel maintaining older version:

  a) For CentOS 6:

    .. code-block:: bash

    	$ yum install -y centos-release-scl
    	$ yum install -y python27

  b) For RHEL 6:

    .. code-block:: bash

    	$ yum install python27

    	# You may need to first enable a repository in order to get python27, with a command like this:
    	#   yum-config-manager --enable rhui-REGION-rhel-server-rhscl
    	#   yum-config-manager --enable rhel-server-rhscl-6-rpms

.. note:: You can also run an :doc:`unattended installation<../unattended-installation>` for the Wazuh manager and API.

Installing Filebeat
-------------------

While Filebeat can be installed from source (`see this doc <https://github.com/elastic/beats/blob/master/CONTRIBUTING.md>`_), the process is more complex than you may like, and it is beyond the scope of Wazuh documentation. We recommend installing Filebeat via repository package, otherwise, you can install it from a binary tarball, that's should work for any Linux distro.  See more `here <https://www.elastic.co/downloads/beats/filebeat>`_.

.. warning::
    In a single-host architecture (where Wazuh server and Elastic Stack are installed in the same system), you may entirely skip installing Filebeat, since Logstash will be able to read the event/alert data directly from the local filesystem without the assistance of a forwarder.

Next steps
----------

Once you have installed the manager, API and Filebeat (only needed for distributed architectures), you are ready to :ref:`install Elastic Stack <installation_elastic>`.
