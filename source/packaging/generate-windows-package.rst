.. Copyright (C) 2019 Wazuh, Inc.

.. _create-windows:

Windows
=======

Wazuh provides an automated way of building Windows packages.

Requirements
^^^^^^^^^^^^

 * Docker
 * Git
 * WiX Toolset.
 * .NET framework 3.5.1
 * Microsoft Windows SDK

To be able to generate the windows msi package, it is necessary to perform two stages.

- Windows agent compilation: You will need a ``Unix`` host with docker and git installed.
- Windows msi package generation: You will need a ``Windows`` host with WiX Toolset,.NET framework 3.5.1 and Microsoft Windows SDK.

Compiling windows agent
^^^^^^^^^^^^^^^^^^^^^^^

Download our wazuh-packages repository from GitHub and go to the ``windows`` directory.

.. code-block:: console

    $ git clone https://github.com/wazuh/wazuh-packages && cd wazuh-packages/windows

Execute the ``generate_compiled_windows_agent.sh`` script, with the different options you desire. This script will build a Docker
image with all the necessary tools to compile and obtain the Windows agent compiled in a zip file :

.. code-block:: console

  #  ./generate_compiled_windows_agent.sh -h

  Usage: ./generate_compiled_windows_agent.sh [OPTIONS]

      -b, --branch <branch>     [Required] Select Git branch [${BRANCH}]. By default: master."
      -j, --jobs <number>       [Optional] Change number of parallel jobs when compiling the Windows agent. By default: 4."
      -r, --revision <rev>      [Optional] Package revision. By default: 1."
      -s, --store <path>        [Optional] Set the directory where the package will be stored. By default the current path."
      -d, --debug               [Optional] Build the binaries with debug symbols. By default: no."
      -h, --help                Show this help."

Below, you will find an example of how to build a compiled Windows agent.

.. code-block:: console

  # ./generate_compiled_windows_agent.sh -b v3.11.0 -s /tmp -r myrevision

.. note::
    The ``-s`` parameter needs an absolute path. In this path you will get the zip with the compiled agent

Generating msi package
^^^^^^^^^^^^^^^^^^^^^^

Once you have obtained the zip with the compiled agent, You need to copy it along with ``generate_wazuh_msi.ps1`` script to the Windows host.

For versions 5 or higher of Windows powershell you can use the following command to unzip the Windows agent:

.. code-block:: console

  # Expand-Archive -LiteralPath .\compiled_agent.zip .\

Then copy the ``generate_wazuh_msi.ps1`` script into the ``src/win32`` directory.

.. code-block:: console

  # cp generate_wazuh_msi.ps1 .\[AGENT_UNCOMPRESSED_FOLDER]\src\win32

Execute the ``generate_wazuh_msi.ps1`` script, with the different options you desire:

.. code-block:: console

  # cd .\[AGENT_UNCOMPRESSED_FOLDER]\src\win32
  # .\generate_wazuh_msi.ps1

  This tool can be used to generate the Windows Wazuh agent msi package.
      PARAMETERS TO BUILD WAZUH-AGENT MSI:
          1. OPTIONAL_REVISION: 1 or different
          2. SIGN: yes or no.
      OPTIONAL PARAMETERS:
          3. WIX_TOOLS_PATH: Wix tools path
          4. SIGN_TOOLS_PATH: sign tools path

      USAGE:
          ./generate_wazuh_msi.ps1  -OPTIONAL_REVISION {{ REVISION }} -SIGN {{ yes|no }} -WIX_TOOLS_PATH {{ PATH }} -SIGN_TOOLS_PATH {{ PATH }}

Below, you will find an example of how to build a Windows msi package.

.. code-block:: console

  # ./generate_wazuh_msi.ps1 -OPTIONAL_REVISION my.revision -SIGN no

.. note::

  If the ``WIX_TOOLS`` and/or ``SIGN_TOOLS`` binaries are not added to the environment PATH, it will be necessary to specify the path,
  as shown in the following example:

  .. code-block:: console

    # ./generate_wazuh_msi.ps1 -OPTIONAL_REVISION my.revision -SIGN yes -WIX_TOOLS_PATH C:\path_to_wix_tools_binary_files -SIGN_TOOLS_PATH C:\path_to_sign_tools_binary_files