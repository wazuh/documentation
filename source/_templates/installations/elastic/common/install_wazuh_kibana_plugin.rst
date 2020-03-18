.. Copyright (C) 2020 Wazuh, Inc.

.. tabs::


    .. tab:: Install from URL


      .. code-block:: console

        # sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-3.11.4_7.6.0.zip



    .. tab:: Install from the local file


      .. code-block:: console

        # sudo -u kibana /usr/share/kibana/bin/kibana-plugin install file:///path/wazuhapp-3.11.4_7.6.0.zip



.. note:: The `path` must have *read* permissions for *others*. E.g: The directory `/tmp/` will accomplish this.

.. End of install_wazuh_kibana_plugin.rst
