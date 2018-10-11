.. Copyright (C) 2018 Wazuh, Inc.

.. _ossec_remoted_state_file:

ossec-remoted state file
========================

The statistical file for **ossec-remoted** is ``ossec-remoted.state`` and it's located under the Wazuh installation directory (``/var/ossec/var/run/ossec-remoted.state``).

This file provides information about the **ossec-remoted** daemon like the queue size, discarded messages or the number of TCP sessions among others. By default, this file is updated **every 5 seconds** but this interval can be changed with the ``remoted.state_interval`` variable in the ``internal_options.conf`` file. For further information please visit the :ref:`internal configuration <reference_internal_options>` page.

.. note:: The ``ossec-remoted.state`` statistical file is only available in managers.

Below you can see an example file:

.. code-block:: bash

    # State file for ossec-remoted
    # Updated every 5 seconds.

    # Queue size
    queue_size='0'

    # Total queue size
    total_queue_size='131072'

    # TCP sessions
    tcp_sessions='0'

    # Events sent to Analysisd
    evt_count='7383'

    # Control messages received
    ctrl_msg_count='270'

    # Discarded messages
    discarded_count='0'

    # Messages sent
    msg_sent='1267'
