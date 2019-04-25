.. Copyright (C) 2019 Wazuh, Inc.

.. _ossec_analysisd_state_file:

ossec-analysisd state file
==========================

The statistical file for **ossec-analysisd** is ``ossec-analysisd.state`` and it's located under the Wazuh installation directory (``/var/ossec/var/run/ossec-analysisd.state``).

This file shows the information relative to the status of the **Analysisd daemon**, displaying real time data. It can help to analyse situations where you need to troubleshoot problems related to getting less events or alerts as expected.

By default, this file is updated **every 5 seconds** but this interval can be changed with the ``analysisd.state_interval`` variable in the ``internal_options.conf`` file. For further information please visit the :ref:`internal configuration <reference_internal_options>` page.

.. note:: The ``ossec-analysisd.state`` statistical file is **only** available in managers.

Below you can see an example file:

.. code-block:: bash

    # State file for ossec-analysisd

    # Total events decoded
    total_events_decoded='5'

    # Syscheck events decoded
    syscheck_events_decoded='0'
    syscheck_edps='0'

    # Syscollector events decoded
    syscollector_events_decoded='0'
    syscollector_edps='0'

    # Rootcheck events decoded
    rootcheck_events_decoded='0'
    rootcheck_edps='0'

    # Hostinfo events decoded
    hostinfo_events_decoded='0'
    hostinfo_edps='0'

    # Other events decoded
    other_events_decoded='5'
    other_events_edps='1'

    # Events processed (Rule matching)
    events_processed='5'
    events_edps='1'

    # Events received
    events_received='5'

    # Events dropped
    events_dropped='0'

    # Alerts written to disk
    alerts_written='0'

    # Firewall alerts written to disk
    firewall_written='0'

    # FTS alerts written to disk
    fts_written='0'

    # Syscheck queue
    syscheck_queue_usage='0.00'

    # Syscheck queue size
    syscheck_queue_size='16384'

    # Syscollector queue
    syscollector_queue_usage='0.00'

    # Syscollector queue size
    syscollector_queue_size='16384'

    # Rootcheck queue
    rootcheck_queue_usage='0.00'

    # Rootcheck queue size
    rootcheck_queue_size='16384'

    # Hostinfo queue
    hostinfo_queue_usage='0.00'

    # Hostinfo queue size
    hostinfo_queue_size='16384'

    # Event queue
    event_queue_usage='0.00'

    # Event queue size
    event_queue_size='16384'

    # Rule matching queue
    rule_matching_queue_usage='0.00'

    # Rule matching queue size
    rule_matching_queue_size='16384'

    # Alerts log queue
    alerts_queue_usage='0.00'

    # Alerts log queue size
    alerts_queue_size='16384'

    # Firewall log queue
    firewall_queue_usage='0.00'

    # Firewall log queue size
    firewall_queue_size='16384'

    # Statistical log queue
    statistical_queue_usage='0.00'

    # Statistical log queue size
    statistical_queue_size='16384'

    # Archives log queue
    archives_queue_usage='0.00'

    # Archives log queue size
    archives_queue_size='16384'

.. note:: As of Wazuh v3.7.0, the Analysis engine received support for multithreaded processing. You can read more about how the daemon works now on it's :ref:`reference documentation <ossec-analysisd-structure>`.
