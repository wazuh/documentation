.. Copyright (C) 2020 Wazuh, Inc.

.. _wazuh_puppet_module:

Wazuh Puppet module
===================

This `module <https://github.com/wazuh/wazuh-puppet>`_ has been authored by Nicolas Zin and updated by Jonathan Gazeley and Michael Porter. Wazuh has forked it with the purpose of maintaining it. Thank you to the authors for the contribution.

Install Wazuh module
--------------------

Download and install the Wazuh module from Puppet Forge:

  .. code-block:: console

    # puppet module install wazuh-wazuh --version |WAZUH_LATEST_PUPPET|

  .. code-block:: none
    :class: output

    Notice: Preparing to install into /etc/puppet/modules ...
    Notice: Downloading from https://forgeapi.puppetlabs.com ...
    Notice: Installing -- do not interrupt ...
    /etc/puppet/modules
    └─┬ wazuh-wazuh (v|WAZUH_LATEST_PUPPET|)
      ├── puppet-nodejs (v7.0.0)
      ├── puppet-selinux (v1.6.1)
      ├── puppetlabs-apt (v6.3.0)
      ├─┬ puppetlabs-concat (v5.3.0)
      │ └── puppetlabs-translate (v1.2.0)
      ├── puppetlabs-firewall (v1.15.1)
      ├── puppetlabs-stdlib (v5.2.0)
      └── stahnma-epel (v1.3.1)

This module installs and configures Wazuh agent and manager.

Install manager via Puppet
--------------------------

The manager is configured by installing the ``wazuh::manager`` class, and optionally using:

 - ``wazuh::command``: to define active response command (like ``firewall-drop.sh``).
 - ``wazuh::activeresponse``: to link rules to active response commands.
 - ``wazuh::addlog``: to define additional log files to monitor.

.. warning::

  On Debian-based operating systems, we will have to add the following section to the ``/etc/puppetlabs/code/environments/production/modules/wazuh/manifests/repo.pp`` file for proper execution:

  ``server => 'pgp.mit.edu'``. Line 9 to 12, do not forget the ``,`` after source entry.

  .. code-block:: puppet

    apt::key { 'wazuh':
        id     => '0DCFCA5547B19D2A6099506096B3EE5F29111145',
        source => 'https://packages.wazuh.com/key/GPG-KEY-WAZUH',
        server => 'pgp.mit.edu'
      }

Here is an example of a manifest ``wazuh-manager.pp``

  .. code-block:: puppet

    node "server.yourhost.com" {
      class { 'wazuh::manager':
        ossec_smtp_server => 'localhost',
        ossec_emailto => ['user@mycompany.com'],
      }

      wazuh::command { 'firewallblock':
        command_name       => 'firewall-drop',
        command_executable => 'firewall-drop.sh',
        command_expect     => 'srcip'
      }

      wazuh::activeresponse { 'blockWebattack':
          command_name => 'firewall-drop',
          ar_level     => 9,
          ar_agent_id  => 123,
          ar_rules_id  => [31153,31151],
          ar_repeated_offenders => '30,60,120'
      }

      wazuh::addlog { 'monitorLogFile':
        logfile => '/var/log/secure',
        logtype => 'syslog'
      }
    }

Place the file at ``/etc/puppetlabs/code/environments/production/manifests/`` in your Puppet master and it will be executed in the specified node after the *runinterval* time set in puppet.conf. However, if you want to run it first, try the following command in the Puppet agent.

  .. code-block:: console

    # puppet agent -t

Install agent via Puppet
------------------------

The agent is configured by installing the ``wazuh::agent`` class.

Here is an example of a manifest ``wazuh-agent.pp`` (please replace with your IP address)

  .. code-block:: puppet

    node "client.yourhost.com" {

      class { "wazuh::agent":
        wazuh_register_endpoint => "192.168.209.166",
        wazuh_reporting_endpoint => "192.168.209.167"
      }

    }

Place the file at ``/etc/puppetlabs/code/environments/production/manifests/`` in your Puppet master and it will be executed in the specified node after the *runinterval* time set in puppet.conf. However, if you want to run it first, try the following command in the Puppet agent.

  .. code-block:: console

    # puppet agent -t

Reference Wazuh puppet
----------------------

+-----------------------------------------------------------------+---------------------------------------------+
| Sections                                                        | Functions                                   |
+=================================================================+=============================================+
| :ref:`Wazuh manager class <reference_wazuh_manager_class>`      | :ref:`email_alert <ref_server_email_alert>` |
|                                                                 |                                             |
|                                                                 | :ref:`command <ref_server_command>`         |
|                                                                 |                                             |
|                                                                 | :ref:`activeresponse <ref_server_ar>`       |
|                                                                 |                                             |
|                                                                 | :ref:`addlog <ref_server_addlog>`           |
+-----------------------------------------------------------------+---------------------------------------------+
| :ref:`Wazuh agent class <reference_wazuh_agent_class>`          | :ref:`addlog <ref_agent_addlog>`            |
|                                                                 |                                             |
|                                                                 |                                             |
+-----------------------------------------------------------------+---------------------------------------------+
| :ref:`ossec_scanpaths configuration <reference_ossec_scanpaths>`|                                             |
+-----------------------------------------------------------------+---------------------------------------------+

.. topic:: Contents

 .. toctree::
    :maxdepth: 1

    reference-wazuh-puppet/ossec-scanpaths
    reference-wazuh-puppet/wazuh-agent-class
    reference-wazuh-puppet/wazuh-manager-class
