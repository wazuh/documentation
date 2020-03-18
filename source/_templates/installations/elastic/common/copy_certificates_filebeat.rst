.. Copyright (C) 2020 Wazuh, Inc.

In section **Installing Elasticsearch**, the ``cert.zip`` file was created. The file must be copied into the Wazuh server host, for example, using ``scp``. This guide assumes that the file is placed in ~/ (home user folder).

.. code-block:: console

  # mkdir /etc/filebeat/certs/ca -p
  # zip -d ~/certs.zip "ca/ca.key"
  # unzip ~/certs.zip -d ~/certs
  # cp -R ~/certs/ca/ ~/certs/filebeat/* /etc/filebeat/certs/
  # chmod -R 500 /etc/filebeat/certs
  # chmod 400 /etc/filebeat/certs/ca/ca.* /etc/filebeat/certs/filebeat.*
  # rm -rf ~/certs/ ~/certs.zip

.. End of copy_certificates_filebeat.rst
