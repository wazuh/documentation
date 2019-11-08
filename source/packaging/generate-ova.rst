.. Copyright (C) 2019 Wazuh, Inc.

.. _create-ova:

Generate Wazuh virtual machine
==============================

Wazuh provides an automated way of generating a Virtual machine in OVA format that is ready to run a Wazuh manager and ELK.

To create the virtual machine follow these steps:

Requirements
^^^^^^^^^^^^

 * `Virtual Box <https://www.virtualbox.org/manual/UserManual.html#installation>`_
 * `Vagrant <https://www.vagrantup.com/docs/installation/>`_
 * `Git <https://git-scm.com/book/en/v2/Getting-Started-Installing-Git>`_
 * `Python <https://www.python.org/download/releases/2.7/>`_

Download our wazuh-packages repository from GitHub and go to the ova directory.

.. code-block:: console

 $ git clone https://github.com/wazuh/wazuh-packages && cd wazuh-packages/ova

Execute the ``generate_ova.sh`` script, with the different options you desire.

.. code-block:: console

  $ ./generate_wazuh_packages.sh -h

  OPTIONS:
       -b, --build            [Required] Build the OVA and OVF.
       -v, --version          [Required] Version of wazuh to install on VM.
       -e, --elastic-version  [Required] Elastic version to download inside VM.
       -r, --repository       [Required] Status of the packages [stable/unstable]
       -c, --clean            [Optional] Clean the local machine.
       -h, --help             [  Util  ] Show this help.

The options for the repository indicates whether the packages used to install Wazuh are the production ones or not.

 * Stable: The OVA uses released packages.
 * Unstable: The OVA uses not released packages.

Below, you will find some examples of how to build a Wazuh virtual machine.

.. code-block:: console

  # ./generate_ova.sh -b -v 3.11.0 -e 7.4.0 -r stable

This will generate a Virtual machine with Wazuh manager 3.11.0 and ELK 7.4.0 installed using stable packages

.. code-block:: console

  # ./generate_ova.sh -b -v 3.11.0 -e 7.4.0 -r unstable -c

This will generate a Virtual machine with Wazuh manager 3.11.0 and ELK 7.4.0 installed using unstable packages and generate the sha512 checksum
