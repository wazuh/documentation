.. Copyright (C) 2015, Wazuh, Inc.

.. meta::
  :description: Find out how to configure Active responses in this section of the Wazuh documentation. 

.. _remediation-examples:

Configuration
=============

#. `Basic usage`_
#. `Windows automatic remediation`_
#. `Block an IP with PF`_
#. `Add an IP to the iptables deny list`_
#. `Active response for a specified period of time`_
#. `Active response that will not be undone`_


Basic usage
-----------

An active response is configured in the :ref:`ossec.conf <reference_ossec_conf>` file in the :ref:`Active Response <reference_ossec_active_response>` and :ref:`Command <reference_ossec_commands>` sections.

In this example, the ``restart-wazuh`` command is configured to use the ``restart-wazuh`` script with no data element.  The active response is configured to initiate the ``restart-wazuh`` command on the local host when the rule with ID 10005 fires.  This is a *Stateless* response as no timeout parameter is defined.

Command::

  <command>
    <name>restart-wazuh</name>
    <executable>restart-wazuh</executable>
  </command>

Active response::

  <active-response>
    <command>restart-wazuh</command>
    <location>local</location>
    <rules_id>10005</rules_id>
  </active-response>

Windows automatic remediation
-----------------------------

In this example, the ``win_route-null`` command is configured to use the ``route-null.exe`` script.  The active response is configured to initiate the ``win_route-null`` command on the local host when the rule has a higher alert level than 7.  This is a *Stateful* response with a timeout set at 900 seconds.

Command::

  <command>
    <name>win_route-null</name>
    <executable>route-null.exe</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

Active response::

  <active-response>
    <command>win_route-null</command>
    <location>local</location>
    <level>8</level>
    <timeout>900</timeout>
  </active-response>


Block an IP with PF
-------------------

In this example, the ``pf-block`` command is configured to use the ``pf`` script.  The active response is configured to initiate the ``pf-block`` command on agent 001 when a rule in either the *"authentication_failed"* or *"authentication_failures"* rule group fires.  This is a *Stateless* response as no timeout parameter is defined.

Command::

  <command>
    <name>pf-block</name>
    <executable>pf</executable>
  </command>

Active response::

  <active-response>
    <command>pf-block</command>
    <location>defined-agent</location>
    <agent_id>001</agent_id>
    <rules_group>authentication_failed|authentication_failures</rules_group>
  </active-response>

Add an IP to the iptables deny list
-----------------------------------

In this example, the ``firewall-drop`` command is configured to use the ``firewall-drop`` script.  The active response is configured to initiate the ``firewall-drop`` command on **all** systems when a rule in either the *"authentication_failed"* or *"authentication_failures"* rule group fires on **any** system.  This is a *Stateful* response with a timeout of 700 seconds.  The ``<repeated_offenders>`` parameter in agent side increases the timeout period for each subsequent offense by a specific IP address.

Command::

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

Active response - on the Manager side::

  <active-response>
    <command>firewall-drop</command>
    <location>all</location>
    <rules_group>authentication_failed|authentication_failures</rules_group>
    <timeout>700</timeout>
  </active-response>

Active response - on the Agent side::

  <active-response>
    <repeated_offenders>30,60,120</repeated_offenders>
  </active-response>


.. note:: The ``<repeated_offenders>`` parameter is specified in **minutes** rather than **seconds**.


Active response for a specified period of time
-----------------------------------------------

The action of a stateful response continues for a specified period of time.

In this example, the ``host-deny`` command is configured to use the ``host-deny`` script.  The active response is configured to initiate the ``host-deny`` command on the local host when a rule with a higher alert level than 6 is fired.

Command::

  <command>
    <name>host-deny</name>
    <executable>host-deny</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

Active response::

  <active-response>
    <command>host-deny</command>
    <location>local</location>
    <level>7</level>
    <timeout>600</timeout>
  </active-response>

More information: :ref:`command <reference_ossec_commands>`

Active response that will not be undone
---------------------------------------

The action of a stateless command is a one-time action that will not be undone.

In this example, the ``mail-test`` command is configured to use the ``mail-test`` script.  The active response is configured to initiate the ``mail-test`` command on the server when the rule with ID 1002 fires.

Command::

  <command>
    <name>mail-test</name>
    <executable>mail-test</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

Active response::

  <active-response>
      <command>mail-test</command>
      <location>server</location>
      <rules_id>1002</rules_id>
   </active-response>
