.. Copyright (C) 2019 Wazuh, Inc.

.. _create-kibana-app:

Generate Wazuh Kibana App packages
==================================

Wazuh provides an automated way of building our Kibana app packages.

To create a Kibana app package follow these steps:

Requirements
^^^^^^^^^^^^

 * Docker
 * Git

Download our wazuh-packages repository from GitHub and go to the wazuhapp directory.

.. code-block:: console

  $ git clone https://github.com/wazuh/wazuh-packages && cd wazuh-packages/wazuhapp

Execute the ``generate_wazuh_app.sh`` script, with the different options you desire. This script will build a Docker image with all the necessary tools to create the Kibana App package and run a container that will build it:

.. code-block:: console

  $ ./generate_wazuh_app.sh -h

  Usage: ./generate_wazuh_app.sh [OPTIONS]

      -b, --branch <branch>     [Required] Select Git branch or tag e.g.v3.11.0-7.4.0
      -s, --store <path>        [Optional] Set the destination path of package, by defauly wazuhapp/output/
      -r, --revision <rev>      [Optional] Package revision that append to version e.g. x.x.x-rev
      -c, --checksum <path>     [Optional] Generate checksum
      -h, --help                Show this help.

Below, you will find some examples of how to build Kibana App packages.

.. code-block:: console

  # ./generate_wazuh_app.sh -b v3.11.0-7.4.0 -s /wazuh-app -r 1

This will generate a Kibana app package for Wazuh 3.11.0 and ELK 7.4.0 with revision 1 and store it in /wazuh-app.

.. code-block:: console

  # ./generate_wazuh_app.sh -b v3.11.0-7.4.0 -s /wazuh-app -r 1 -c

This will generate a Kibana app package for Wazuh 3.11.0 and ELK 7.4.0 with revision 1, the sha512 checksum and store them in /wazuh-app .

Remember that the branch or tag for the script has to come from our wazuh-kibana-app repository.