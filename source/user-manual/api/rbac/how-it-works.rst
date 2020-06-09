.. Copyright (C) 2020 Wazuh, Inc.

.. _api_rbac_how_it_works:

How it works
============

The operation of RBAC is based on the relationship between three components: **users**, **roles** and **policies** or permissions. Policies are associated with roles, and each user can belong to one or more roles.

Since the policies are not directly related to users, it is not necessary to assign them to each person. Simply assign the user to the appropriate role. The process of updating the permissions of an entire group of users is also made easier thanks to this structure.

After configuring RBAC, there will be groups that can only see and do certain actions on specified resources that have previously been established. It would be ensured that members of a Security-team have 'read' access to all agents, while the Sales-team has 'read' and 'modify' permissions only to agents in their department (but not delete permissions).

Actions, resources and effect
-----------------------------
Policies control API permissions using three elements: actions, resources, and effect.

**Actions** represents a hierarchy of actions that a user may perform. They indicate both the element to which the action belongs and the action itself. The structure they follow looks like the example below, where restarting agent is specified.

.. code-block:: console

      agent:restart

**Resources** are any entity that can be subject to an action. The set of resources is dynamic, but the types are static. Some examples of resources are "agent 001", "agents in group default" or "node of a cluster". The symbol ``*`` can be used as a wildcard to indicate all the resources of a type, instead of specifying them one by one. For example:

.. code-block:: console

    agent:id:001
    node:id:*

**Effect** can only be "allow" or "deny", depending on the effective permission to be applied.

.. note::
    For a complete list of resources and actions, please visit :ref:`RBAC reference <api_rbac_reference>`.

RBAC modes
----------

RBAC in Wazuh can be configured in two different and opposite ways: **black** and **white**. The choice of one mode or another determines what will be the behaviour of the created policies. If the parameter ``effect`` of a policy is set to ``allow``, that policy will be allowed in both black and white mode. If the effect is ``deny``, it will be denied in both black and white. Therefore, the RBAC mode only affects those actions that are not specified within each policy.

- **White list mode:** everything is forbidden. The administrator configure roles to give permissions.
- **Black list mode:** everything is allowed. The administrator configure roles to restrict permissions.
