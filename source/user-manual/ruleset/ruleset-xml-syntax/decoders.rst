.. Copyright (C) 2020 Wazuh, Inc.

.. _decoders_syntax:

Decoders Syntax
===============

The decoders extract the information from the received events.
When an event is received, the decoders separate the information in blocks to prepare them for their subsequent analysis.

Overview
--------

There are many options to configure in decoders:

+-------------------+---------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
| Option            | Values                                                        | Description                                                                                     |
+===================+===============================================================+=================================================================================================+
| `decoder`_        | Name and/or type                                              | Its attributes will be used to define the decoder.                                              |
+-------------------+---------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
| `parent`_         | Any decoder's name                                            | It will reference a parent decoder and the current one will become a child decoder.             |
+-------------------+---------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
| `accumulate`_     | None                                                          | It allows to track events over multiple log messages.                                           |
+-------------------+---------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
| `program_name`_   | Any program name                                              | It defines the name of the program associated with the decoder.                                 |
+-------------------+---------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
| `prematch`_       | Any String or `Regular Expression                             | It will look for a match in the log, in case it does, the decoder will be used.                 |
|                   | <regex.html#regex-os-regex-syntax>`_                          |                                                                                                 |
+-------------------+---------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
| `regex`_          | Any `Regular Expression                                       | The decoder will use this option to find fields of interest and extract them.                   |
|                   | <regex.html#regex-os-regex-syntax>`_                          |                                                                                                 |
+-------------------+---------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
| `order`_          | See `order table <decoders.html#order>`_                      | The values that `regex`_ will extract, will be stored in these groups.                          |
+-------------------+---------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
| `fts`_            | See `fts table <decoders.html#fts>`_                          | Fist time seen.                                                                                 |
+-------------------+---------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
| `ftscomment`_     | Any String                                                    | Adds a comment to fts.                                                                          |
+-------------------+---------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
| `plugin_decoder`_ | See `below <decoders.html#plugin-decoder>`_                   | Specifies a plugin that will do the decoding. Useful when extraction with regex is not          |
|                   |                                                               | feasible.                                                                                       |
+-------------------+---------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
| `use_own_name`_   | True                                                          | Only for child decoders.                                                                        |
+-------------------+---------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
| `json_null_field`_| String                                                        | Adds the option of deciding how a null value from a JSON will be stored.                        |
+-------------------+---------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
| `var`_            | Name for the variable.                                        | Defines variables that can be reused inside the same file.                                      |
+-------------------+---------------------------------------------------------------+-------------------------------------------------------------------------------------------------+

How it works
------------

To understand the inner workings of a decoder, it will be easier through examples like the following:

.. code-block:: console

  Apr 14 19:28:21 gorilla sshd[31274]: Connection closed by 192.168.1.33

.. code-block:: none
  :class: output

  **Phase 1: Completed pre-decoding.
         full event: 'Apr 14 19:28:21 gorilla sshd[31274]: Connection closed by 192.168.1.33'
         timestamp: 'Apr 14 19:28:21'
         hostname: 'gorilla'
         program_name: 'sshd'
         log: 'Connection closed by 192.168.1.33'

  **Phase 2: Completed decoding.
         decoder: 'sshd'
         srcip: '192.168.1.33'

At the beginning of the example is the full log of an event. The log firstly goes through a pre-decoding phase, where general information will be extracted if possible.

Afterwards, the decoder will begin the extraction of information from the log that is left. In this example, the decoder only analyzes: ``Connection closed by 192.168.1.33``.

Before making a custom decoder, the first step should always be running the event log through :ref:`ossec-logtest <ossec-logtest>` to know where to start.


Options
-------

There is many options to configure the decoders:

- `decoder`_
- `parent`_
- `accumulate`_
- `program_name`_
- `prematch`_
- `regex`_
- `order`_
- `fts`_
- `ftscomment`_
- `plugin_decoder`_
- `use_own_name`_
- `json_null_field`_
- `var`_
- `type`_

decoder
^^^^^^^

The attributes listed below define a decoder.


+-----------+---------------------------+
| Attribute | Description               |
+===========+===========================+
| name      | The name of the decoder   |
+-----------+---------------------------+

Example:

Set name of decoder to *ossec*:

.. code-block:: xml

    <decoder name="ossec">
      ...
    </decoder>

parent
^^^^^^

It is used to link a subordinate decoder to its parent. A parent decoder can have many child decoders but take into account that a child decoder cannot be a parent.
It is possible to create what we call `sibling decoders <sibling-decoders.html>`_, which is a handy decoding strategy to handle dynamic logs.


+--------------------+------------------+
| **Default Value**  | n/a              |
+--------------------+------------------+
| **Allowed values** | Any decoder name |
+--------------------+------------------+

Example:

*Decoder_junior* will enter only if *decoder_parent* has previously matched.

.. code-block:: xml

  <decoder name="decoder_junior">
    <parent>decoder_father</parent>
    ...
  </decoder>

accumulate
^^^^^^^^^^^

Allows Wazuh to track events over multiple log messages based on a decoded id.

.. note::

   Requires a regex populating the id field.

+--------------------+--------------------+
| **Example of use** | <accumulate />     |
+--------------------+--------------------+

program_name
^^^^^^^^^^^^^

It defines the name of the program which the decoder is associated with. The program name of a log will be obtained, if possible, in the pre-decoding phase.

+--------------------+--------------------------------------------------------------------+
| **Default Value**  | n/a                                                                |
+--------------------+--------------------------------------------------------------------+
| **Allowed values** | Any `sregex expression <regex.html#sregex-os-match-syntax>`_       |
+--------------------+--------------------------------------------------------------------+

Example:

Define that the decoder is related with the ``syslogd`` process:

.. code-block:: xml

  <decoder name="syslogd_decoder">
    <program_name>syslogd</program_name>
    ...
  </decoder>

prematch
^^^^^^^^^

It attempts to find a match within the log for the string defined. It is used as a condition to enter the decoder, if it finds a match, the current decoder will be used and the search for a decoder will stop and only its child decoders will be able to match. It is important to be as specific as possible to avoid matching with wrong events.

+--------------------+--------------------------------------------------------------------+
| **Default Value**  | n/a                                                                |
+--------------------+--------------------------------------------------------------------+
| **Allowed values** | Any `regex expression <regex.html#regex-os-regex-syntax>`_         |
+--------------------+--------------------------------------------------------------------+

The attribute below is optional, it allows to discard some of the content of the entry.

+--------------------+--------------------+
| Attribute          | Value              |
+====================+====================+
| **offset**         | after_regex        |
+                    +                    +
|                    | after_parent       |
+--------------------+--------------------+

regex
^^^^^

**Regular expressions** or ``regex`` are sequences of characters that define a pattern.
Decoders use them to find words or other patterns into the rules. The decoder will only extract those fields that are contained within parentheses.

An example is this regex that matches any numeral:

.. code-block:: xml

  <regex> [+-]?(\d+(\.\d+)?|\.\d+)([eE][+-]?\d+)? </regex>


+--------------------+--------------------------------------------------------------------+
| **Default Value**  | n/a                                                                |
+--------------------+--------------------------------------------------------------------+
| **Allowed values** | Any `regex expression <regex.html#regex-os-regex-syntax>`_         |
+--------------------+--------------------------------------------------------------------+

When using the ``regex`` label it is mandatory to define an ``order`` label as well. Besides, ``regex`` label requires a ``prematch`` or a ``program_name`` label defined on the same decoder or a ``parent`` with a ``prematch`` or a ``program_name defined`` label defined on it.

The attribute below is optional. It allows to discard some of the content of the entry.

+--------------------+--------------------+
| Attribute          | Value              |
+====================+====================+
| **offset**         | after_regex        |
+                    +                    +
|                    | after_parent       |
+                    +                    +
|                    | after_prematch     |
+--------------------+--------------------+

Example:

Show when a user executed the sudo command for the first time:

.. code-block:: xml

  <decoder name="sudo-fields">
    <parent>sudo</parent>
    <prematch>\s</prematch>
    <regex>^\s*(\S+)\s*:</regex>
    <order>srcuser</order>
    <fts>name,srcuser,location</fts>
    <ftscomment>First time user executed the sudo command</ftscomment>
  </decoder>



order
^^^^^^

It defines what the parenthesis groups contain and the order in which they were received. It requires a ``regex`` label defined on the same decoder.

+--------------------+--------------------------------------------------------------------+
| **Default Value**  | n/a                                                                |
+--------------------+------------+-------------------------------------------------------+
| **Static fields**  | srcuser    | Extracts the source username                          |
+                    +------------+-------------------------------------------------------+
|                    | dstuser    | Extracts the destination (target) username            |
+                    +------------+-------------------------------------------------------+
|                    | user       | An alias to dstuser (only one of the two can be used) |
+                    +------------+-------------------------------------------------------+
|                    | srcip      | Source ip                                             |
+                    +------------+-------------------------------------------------------+
|                    | dstip      | Destination ip                                        |
+                    +------------+-------------------------------------------------------+
|                    | srcport    | Source port                                           |
+                    +------------+-------------------------------------------------------+
|                    | dstport    | Destination port                                      |
+                    +------------+-------------------------------------------------------+
|                    | protocol   | Protocol                                              |
+                    +------------+-------------------------------------------------------+
|                    | id         | Event id                                              |
+                    +------------+-------------------------------------------------------+
|                    | url        | Url of the event                                      |
+                    +------------+-------------------------------------------------------+
|                    | action     | Event action (deny, drop, accept, etc)                |
+                    +------------+-------------------------------------------------------+
|                    | status     | Event status (success, failure, etc)                  |
+                    +------------+-------------------------------------------------------+
|                    | extra_data | Any extra data                                        |
+--------------------+------------+-------------------------------------------------------+
| **Dynamic fields** | Any string not included in the previous list                       |
+--------------------+------------+-------------------------------------------------------+

fts
^^^^

It is used to designate a decoder as one in which the first time it matches the administrator would like to be alerted.

+--------------------+--------------------------------------------------------------------+
| **Default Value**  | n/a                                                                |
+--------------------+------------+-------------------------------------------------------+
| **Allowed values** | location   | Where the log came from                               |
+                    +------------+-------------------------------------------------------+
|                    | srcuser    | Extracts the source username                          |
+                    +------------+-------------------------------------------------------+
|                    | dstuser    | Extracts the destination (target) username            |
+                    +------------+-------------------------------------------------------+
|                    | user       | An alias to dstuser (only one of the two can be used) |
+                    +------------+-------------------------------------------------------+
|                    | srcip      | Source ip                                             |
+                    +------------+-------------------------------------------------------+
|                    | dstip      | Destination ip                                        |
+                    +------------+-------------------------------------------------------+
|                    | srcport    | Source port                                           |
+                    +------------+-------------------------------------------------------+
|                    | dstport    | Destination port                                      |
+                    +------------+-------------------------------------------------------+
|                    | protocol   | Protocol                                              |
+                    +------------+-------------------------------------------------------+
|                    | id         | Event id                                              |
+                    +------------+-------------------------------------------------------+
|                    | url        | Url of the event                                      |
+                    +------------+-------------------------------------------------------+
|                    | action     | Event action (deny, drop, accept, etc)                |
+                    +------------+-------------------------------------------------------+
|                    | status     | Event status (success, failure, etc)                  |
+                    +------------+-------------------------------------------------------+
|                    | extra_data | Any extra data                                        |
+--------------------+------------+-------------------------------------------------------+

Example:

The following decoder will extract the user who generated the alert and the location from where it comes:

.. code-block:: xml

  </decoder>
    <fts>srcuser, location</fts>
    ...
  </decoder>

ftscomment
^^^^^^^^^^^

It adds a comment to a decoder when `<fts>` tag is used.

+--------------------+------------+
| **Default Value**  | n/a        |
+--------------------+------------+
| **Allowed values** | Any string |
+--------------------+------------+

plugin_decoder
^^^^^^^^^^^^^^^

Use a specific plugin decoder to decode the incoming fields. It is useful for particular cases where it would be tricky to extract the fields by using regexes.

+--------------------+--------------------------------------------------------------------+
| **Default Value**  | n/a                                                                |
+--------------------+--------------------------------------------------------------------+
| **Allowed values** | PF_Decoder                                                         |
+                    +--------------------------------------------------------------------+
|                    | SymantecWS_Decoder                                                 |
+                    +--------------------------------------------------------------------+
|                    | SonicWall_Decoder                                                  |
+                    +--------------------------------------------------------------------+
|                    | OSSECAlert_Decoder                                                 |
+                    +--------------------------------------------------------------------+
|                    | JSON_Decoder                                                       |
+--------------------+--------------------------------------------------------------------+

The attribute below is optional, it allows to start the decode process after a particular point of the log.

+--------------------+--------------------+
| Attribute          | Value              |
+====================+====================+
| **offset**         | after_parent       |
+                    +                    +
|                    | after_prematch     |
+--------------------+--------------------+

An example of its use is described at the :doc:`JSON decoder <../json-decoder>` section.

use_own_name
^^^^^^^^^^^^^

Allows setting the name of the child decoder from the name attribute instead of using the name of the parent decoder.

+--------------------+------------+
| **Default Value**  | n/a        |
+--------------------+------------+
| **Allowed values** | true       |
+--------------------+------------+

json_null_field
^^^^^^^^^^^^^^^

Specify how to treat the `NULL` fields coming from the JSON events. Only for the JSON decoder.

+--------------------+-------------------------------------------------------------------------+
| **Default Value**  | string                                                                  |
+--------------------+-------------------------------------------------------------------------+
| **Allowed values** | string (It shows the NULL value as string)                              |
+                    +-------------------------------------------------------------------------+
|                    | discard (It discard NULL fields and doesn't store them into the alert)  |
+                    +-------------------------------------------------------------------------+
|                    | empty (It shows the NULL field as an empty field)                       |
+--------------------+-------------------------------------------------------------------------+

var
^^^

Defines a variable that may be used in any place of the same file.

+----------------+------------------------+
| Attribute      | Value                  |
+================+========================+
| **name**       | Name for the variable. |
+----------------+------------------------+

Example:

.. code-block:: xml

  <var name="header">myprog</var>
  <var name="offset">after_parent</var>
  <var name="type">syscall</var>

  <decoder name="syscall">
    <prematch>^$header</prematch>
  </decoder>

    <decoder name="syscall-child">
      <parent>syscall</parent>
      <prematch offset="$offset">^: $type </prematch>
      <regex offset="after_prematch">(\S+)</regex>
      <order>syscall</order>
    </decoder>

type
^^^^

It sets the type of log that the decoder is going to match.

Example:

Set type of decoder to *syslog*:

.. code-block:: xml

    <decoder>
      <type>syslog</type>
      ...
    </decoder>
