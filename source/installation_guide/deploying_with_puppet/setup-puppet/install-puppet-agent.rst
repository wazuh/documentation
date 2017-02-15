.. _setup_puppet_agent:

Installing Puppet agent
============================

In this section we assume you have already installed APT and Yum Puppet repositories.

Installation on CentOS
^^^^^^^^^^^^^^^^^^^^^^
::

   $ sudo yum install puppet
   $ sudo puppet resource package puppet ensure=latest

Installation on Debian
^^^^^^^^^^^^^^^^^^^^^^
::

   $ sudo apt-get install puppet
   $ sudo apt-get update
   $ sudo puppet resource package puppet ensure=latest

Configuration
^^^^^^^^^^^^^

Add the server value to the ``[main]`` section of the node’s ``/etc/puppet/puppet.conf`` file, replacing ``puppet.example.com`` with your Puppet master’s FQDN::

   [main]
   server = puppet.example.com

Restart the Puppet service::

   $ service puppet restart

Puppet certificates
-------------------

Run Puppet agent to generate a certificate for the Puppet master to sign: ::

   $ sudo puppet agent -t

Log into to your Puppet master, and list the certificates that need approval: ::

   $ sudo puppet cert list

It should output a list with your node’s hostname.

Approve the certificate, replacing ``hostname.example.com`` with your agent node’s name: ::

   $ sudo puppet cert sign hostname.example.com

Back on the Puppet agent node, run the puppet agent again: ::

   $ sudo puppet agent -t

.. note:: Remember the Private Network DNS is a requisite for the correct certificate sign.
