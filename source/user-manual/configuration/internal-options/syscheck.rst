.. _reference_ossec_syschek:


Syscheck
========


+-------------------------+---------------+---------------------------------+
| Options                 | Default value | Allowed values                  |
+=========================+===============+=================================+
| `syscheck.sleep`_       | 2             | A positive number (seconds)     |
+-------------------------+---------------+---------------------------------+
| `syscheck.sleep_after`_ | 15            | Any integer                     |
+-------------------------+---------------+---------------------------------+
| `syscheck.debug`_       | 0             | 0, 1, 2                         |
+-------------------------+---------------+---------------------------------+


``syscheck.sleep``
------------------

This setting determines how long to sleep after reading `syscheck.sleep_after`_ number of files.


.. topic:: Default value

  2

.. topic:: Allowed values

	Any integer

``syscheck.sleep_after``
------------------------

This is the number of files to read before sleeping for `syscheck.sleep`_ seconds.


.. topic:: Default value

  15

.. topic:: Allowed values

	Any integer



``syscheck.debug``
------------------

Syscheck debug options, used in local, server and unix agent installations.


.. topic:: Default value

  0

.. topic:: Allowed values

	0
		No debug
	1
		First level of debug
	2
		Full debugging
