.. Copyright (C) 2020 Wazuh, Inc.

.. code-block:: console

  # yum remove wazuh-agent

There are files marked as configuration files. Due to this designation, the package manager does not remove those files from the filesystem. The complete file removal action is on user's responsibility. It can be done removing the folder ``/var/ossec``.

.. End of include file
