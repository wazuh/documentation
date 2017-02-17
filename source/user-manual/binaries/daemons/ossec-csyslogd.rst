
.. _ossec-csyslogd:

ossec-csyslogd
==============

``ossec-csyslogd`` is a daemon that forwards the Wazuh alerts via syslog.

+------------------------------+---------------------------------+
| Options                      | Descriptions                    |
+==============================+=================================+
| `-c`_                        | Run using a configuration file  |
+------------------------------+---------------------------------+
| `-D <#csyslogd-directory>`__ | Chroot to a directory           |
+------------------------------+---------------------------------+
| `-d <#csyslogd-debug>`__     | Run in debug mode               |
+------------------------------+---------------------------------+
| `-f`_                        | Run in foreground               |
+------------------------------+---------------------------------+
| `-g`_                        | Run as a group                  |
+------------------------------+---------------------------------+
| `-h`_                        | Display the help message        |
+------------------------------+---------------------------------+
| `-t`_                        | Test configuration              |
+------------------------------+---------------------------------+
| `-u`_                        | Run as an user                  |
+------------------------------+---------------------------------+
| `-V`_                        | Version and license information |
+------------------------------+---------------------------------+


``-c``
------

Run ossec-csyslogd using ``<config>`` as the configuration file.

.. topic:: Arguments

  ``-c <config>``

.. topic:: Default

  ``/var/ossec/etc/ossec.conf``



.. _csyslogd-directory:

``-D``
------

Chroot to ``<dir>``.

.. topic:: Arguments

  ``-D <dir>``

.. topic:: Default

  ``/var/ossec``


.. _csyslogd-debug:

``-d``
------

Execute ossec-csyslogd in debug mode. This option can be used multiple times to increase the verbosity of the debug messages.

``-f``
------

Run ``ossec-csyslogd`` in the foreground.

``-g``
------

Run ossec-csyslogd as <group>.

.. topic:: Arguments

  ``-g <group>``


``-h``
------

Display the help message.

``-t``
------

Test configuration.


``-u``
------

Run ``ossec-csyslogd`` as ``<user>``.

.. topic:: Arguments

  ``-u <user>``

.. topic:: Default

  ossecm


``-V``
------

Version and license information.
