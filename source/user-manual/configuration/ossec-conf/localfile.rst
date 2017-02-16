.. _reference_ossec_localfile:


Local file
==========

.. topic:: XML section name

	.. code-block:: xml

		<localfile>

Configuration required to collect logs from files, windows events and command executions.

+-----------------------+--------------------------------------------------------------------------------------------+
| Options               | Allowed values                                                                             |
+=======================+============================================================================================+
| `location`_           | Any log file                                                                               |
+-----------------------+--------------------------------------------------------------------------------------------+
| `command`_            | Any commandline and arguments                                                              |
+-----------------------+--------------------------------------------------------------------------------------------+
| `alias`_              | Any string                                                                                 |
+-----------------------+--------------------------------------------------------------------------------------------+
| `frequency`_          | A positive number (seconds)                                                                |
+-----------------------+--------------------------------------------------------------------------------------------+
| `check_diff`_         | n/a                                                                                        |
+-----------------------+--------------------------------------------------------------------------------------------+
| `only-future-events`_ | yes, no                                                                                    |
+-----------------------+--------------------------------------------------------------------------------------------+
| `query`_              | Any XPATH query following the `event                                                       |
|                       | schema <https://msdn.microsoft.com/en-us/library/windows/desktop/aa385201(v=vs.85).aspx>`_ |
+-----------------------+--------------------------------------------------------------------------------------------+
| `log_format`_         | syslog, snort-full, snort-fast, squid, iis,                                                |
|                       |                                                                                            |
|                       | eventlog, eventchannel, mysql_log,                                                         |
|                       |                                                                                            |
|                       | postgresql_log, nmapg, apache, command,                                                    |
|                       |                                                                                            |
|                       | full_command, djb-multilog, multi-line                                                     |
+-----------------------+--------------------------------------------------------------------------------------------+

``location``
------------

Specify the location of the log to be read. ``strftime`` formats may be used for log file names.

For instance, a log file named ``file.log-2017-01-22`` could be referenced with ``file.log-%Y-%m-%d``.

Wildcards may be used on non-Windows systems. When wildcards are used, the log files must exist at the time
``ossec-logcollector`` is started. It will not automatically begin monitoring new log files.

``strftime`` and wildcards cannot be used on the same entry.

.. topic:: Default value

	n/a

.. topic:: Allowed values

	Any log file


``command``
-----------

The command to be run. All output from this command will be read as one or more log messages depending on whether
command or full_command is used.


.. topic:: Default value

	n/a

.. topic:: Allowed values

	Any commandline and arguments

``alias``
---------

An alias to identify the command. This will replace the command in the log message.
For example ``<alias>usb-check</alias>`` would replace:

.. code-block:: xml

   ossec: output: 'reg QUERY HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR':

with:

.. code-block:: xml

   ossec: output: 'usb-check':


.. topic:: Default value

	n/a

.. topic:: Allowed values

	Any string

``frequency``
-------------

The minimum time in seconds between command runs. The command will probably not run every ``frequency``
seconds exactly, but the time between runs will not be shorter than this setting.
This is used with command and full_command.


.. topic:: Default value

	n/a

.. topic:: Allowed values

	Any positive number, time in seconds

``check_diff``
--------------

The output from an event will be stored in an internal database. Every time the same event is received, the output is compared
to the previous output. If the output has changed an alert will be generated.


.. topic:: Default value

	n/a

.. topic:: Allowed values

	n/a

``only-future-events``
----------------------


Only used with the ``eventchannel`` log format. By default, when OSSEC starts the eventchannel log format will read all
events that ossec-logcollector missed since it was last stopped.
It is possible to set ``only-future-events`` to ``yes`` in order to prevent this behaviour. When set to ``yes``, OSSEC will only
receive events that occured after the start of logcollector.

.. code-block:: xml

	<localfile>
	  <location>System</location>
	  <log_format>eventchannel</log_format>
	  <only-future-events>yes</only-future-events>
	</localfile>


.. topic:: Default value

  n/a

.. topic:: Allowed values

  The option accepted are: yes, no

``query``
---------

Only used with the ``eventchannel`` log format. It is possible to specify an XPATH query following the event
schema in order to filter the events that OSSEC will process.
For example, the following configuration will only process events with an ID of 7040:

.. code-block:: xml

  <localfile>
     <location> System</location>
     <log_format>eventchannel</log_format>
     <query>Event/System[EventID=7040]</query>
  </localfile>


.. topic:: Default value

  n/a

.. topic:: Allowed values

	Any XPATH query following the `event schema <https://msdn.microsoft.com/en-us/library/windows/desktop/aa385201(v=vs.85).aspx>`_

``log_format``
--------------


The format of the log being read.

.. note::

  If the log has one entry per line, use syslog.

.. topic:: Default value

	.. code-block:: xml

	  	<log_format>syslog</log_format>

.. topic:: Allowed values

  syslog
      This format is for plain text files in a syslog-like format. It can also be used when there is no support for the logging format, and the logs are single line messages.
  snort-full
      This is used for Snort’s full output format.
  snort-fast
      This is used for Snort's fast output format.
  squid
      This is used for squid logs.
  iis
      This is used for IIS logs.
  eventlog
      This is used for Microsoft Windows eventlog format.
  eventchannel
      This is used for Microsoft Windows eventlogs, using the new EventApi. This allows OSSEC to monitor both standard “Windows” eventlogs and more recent "Application and Services" logs. This support was added in 2.8.

  .. warning::

      eventchannel cannot be used on Windows systems older than Vista.

  mysql_log
      This is used for ``MySQL`` logs. It does not support multi-line logs.
  postgresql_log:
      This is used for ``PostgreSQL`` logs. It does not support multi-line logs.
  nmapg
      This is used for monitoring files conforming to the grepable output from ``nmap``.
  apache
      This format is for apache's default log format.
  command
      This format will be the output from the command (as run by root) defined by command.
      Each line of output will be treated as a separate log.
  full_command
      This format will be the output from the command (as run by root) defined by command. The entire output will be treated as a single log.


  .. warning::

      ``command`` and ``full_command`` cannot be used in the agent.conf, and must be configured in each system's ossec.conf.

  **djb-multilog**

  multi-line
      This option will allow applications that log multiple lines per event to be monitored. This format requires the number of lines to be consistent.
      ``multi-line:`` is followed by the number of lines in each log entry. Each line will be combined with the previous lines until all lines are gathered.
      There may be multiple timestamps in a finalized event.

      The format allowed is: <log_format>multi-line: NUMBER</log_format>

      Example:

      Log messages:

      .. code-block:: console

         Aug 9 14:22:47 hostname log line one
         Aug 9 14:22:47 hostname log line two
         Aug 9 14:22:47 hostname log line four
         Aug 9 14:22:47 hostname log line three
         Aug 9 14:22:47 hostname log line five

      Log message as analyzed by ossec-analysisd:

      .. code-block:: console

         Aug 9 14:22:47 hostname log line one Aug 9 14:22:47 hostname log line two Aug 9 14:22:47 hostname log line three Aug 9 14:22:47 hostname log line four Aug 9 14:22:47 hostname log line five
