.. Copyright (C) 2020 Wazuh, Inc.

To uninstall the agent in Solaris 11:

  .. code-block:: console

    # pkg uninstall wazuh-agent

.. note:: There are two known issues in Solaris 11:
  - If you uninstall the Wazuh agent from Solaris 11.4 or greater, the Solaris 11 package manager does not remove the group ``ossec`` from the system. You can remove it manually with ``groupdel ossec``.
  - If you want to upgrade the Wazuh agent in Solaris 11, you will need to stop first the service. For that ``/var/ossec/bin/ossec-control stop``.

.. End of include file
