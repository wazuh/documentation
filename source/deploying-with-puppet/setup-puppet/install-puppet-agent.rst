.. Copyright (C) 2018 Wazuh, Inc.

.. _setup_puppet_agent:

Installing Puppet agent
============================

In this section we assume you have already installed the ``apt`` or ``yum`` Puppet repository on your agent system in the same way that you did on your Puppet Server.

Installation on CentOS/RHEL/Fedora
------------------------------------

Install the Puppet yum repository and then the "puppet-agent" package. See this `index <https://yum.puppetlabs.com/>`_ to find the correct rpm file needed to install the puppet repo for your Linux distribution. For example, to install Puppet 5 for CentOS 7 or RHEL 7, do the following:

.. code-block:: console

   # rpm -ivh https://yum.puppetlabs.com/puppet5/puppet5-release-el-7.noarch.rpm
   # yum -y install puppet-agent

.. note:: 

  For a correct installation we recommend the use of Puppet versions equal or greater than 5. 

Installation on Debian/Ubuntu
------------------------------

Install ``curl``, ``apt-transport-https`` and ``lsb-release``:

.. code-block:: console

	# apt-get update
	# apt-get install curl apt-transport-https lsb-release

Get the appropriate Puppet apt repository, and then the "puppet-agent" package. See https://apt.puppetlabs.com to find the correct deb file to install the puppet repo for your Linux distribution.

.. code-block:: console

  # wget https://apt.puppetlabs.com/puppet5-release-xenial.deb
  # dpkg -i puppet5-release-xenial.deb
  # apt update
  # apt-get install -y puppet-agent

.. note:: For a correct installation we recommend the use of Puppet versions equal or greater than 5. 


.. note:: The releases supported by the manifest to install Wazuh are as follows: 

      Ubuntu: **precise | trusty | vivid | wily | xenial | yakketi**

      Debian: **jessie | wheezy | stretch | sid**
  


Configuration
^^^^^^^^^^^^^

Add the server value to the ``[main]`` section of the node’s ``/etc/puppetlabs/puppet/puppet.conf`` file, replacing ``puppet.example.com`` with your Puppet Server’s FQDN::

   [main]
   server = puppet.example.com

Restart the Puppet service:

.. code-block:: console

   # /opt/puppetlabs/bin/puppet resource service puppet ensure=running enable=true
