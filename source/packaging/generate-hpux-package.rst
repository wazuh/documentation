.. Copyright (C) 2019 Wazuh, Inc.

.. _create-hpux:

HPUX
====

Wazuh provides an automated way of building HPUX packages, keep in mind that to build an HPUX package you must run this tool in an HPUX system.

To create an HPUX package follow these steps:

Requirements
^^^^^^^^^^^^

 * GCC: download.
 * depothelper: download.

Download our wazuh-packages repository from GitHub and go to the ``hpux`` directory.

.. code-block:: console

 $ curl -L https://github.com/wazuh/wazuh-packages/tarball/master | tar zx
 $ cd wazuh-wazuh-packages-*
 $ cd hp-ux

Execute the ``generate_wazuh_packages.sh`` script, with the different options you desire.

.. code-block:: console

  # ./generate_wazuh_packages.sh -h

  Usage: ./generate_wazuh_packages.sh [OPTIONS]

      -e Install all the packages necessaries to build the TAR package
      -b <branch> Select Git branch. Example v3.11.2
      -s <tar_directory> Directory to store the resulting tar package. By default, an output folder will be created.
      -p <tar_home> Installation path for the package. By default: /var
      -c,  --checksum Compute the SHA512 checksum of the TAR package.
      -d <path_to_depot>, --depot Change the path to depothelper package (by default current path).
      -h Shows this help

Below, you will find an example of how to build HPUX packages.

First, install the needed dependencies:

.. code-block:: console

  # ./generate_wazuh_packages.sh -e

Below, you will find some examples of how to build an HPUX package.

.. code-block:: console

  # ./generate_wazuh_packages.sh -b v3.11.2

This will generate a 3.11.2 Wazuh agent HPUX package.

.. code-block:: console

  # ./generate_wazuh_packages.sh -b v3.11.2 -c

This will generate a 3.11.2 Wazuh agent HPUX package with checksum.

.. code-block:: console

  # ./generate_wazuh_packages.sh -b v3.11.2  -p /opt

This will generate a 3.11.2 Wazuh agent HPUX package with ``opt`` as installation directory.
