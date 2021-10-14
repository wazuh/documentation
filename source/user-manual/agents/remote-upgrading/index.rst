.. Copyright (C) 2021 Wazuh, Inc.

.. _remote-upgrading:

Remote upgrading
==================

.. topic:: Contents

    .. toctree::
        :maxdepth: 2

        upgrading-agent
        agent-upgrade-module
        custom-repository
        create-custom-wpk/create-wpk-key
        install-custom-wpk
        wpk-list

With version 3.0.0, agents now have the ability to be upgraded remotely. This upgrade is performed by the manager which sends each registered agent a **WPK** (Wazuh signed package) file
that contains the files needed to upgrade agent to the new version. This securely and simply applies upgrades across your installation without the need to access each agent individually.

Wazuh provides access to an updated WPK repository for each new release. All available WPK files can be found :doc:`here <./wpk-list>`.

Custom repositories may also be added by following the steps described in :doc:`Adding custom repository <./custom-repository>`.

.. note:: Since v4.1.0, the upgrade procedure is performed by the :ref:`Agent upgrade module<agent-upgrade-module>`.
