.. Copyright (C) 2018 Wazuh, Inc.

.. _decoders_syntax:

Decoders Syntax
===============

The decoders extract the information from the received events.
When an event is received, the decoders separate the information in blocks to prepare them for their subsequent analysis.

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
- `location`_
- `var`_

decoder
^^^^^^^

The attributes listed below define a decoder.

+-----------+---------------------------+
| Attribute | Description               |
+===========+===========================+
| name      | The name of the decoder   |
+-----------+---------------------------+
| type      | The type of the decoder   |
+-----------+---------------------------+

Example:

Set name and type of decoder to *ossec*:

  .. code-block:: xml

    <decoder name="ossec" type ="ossec">
      ...
    </decoder>

parent
^^^^^^

It is used to link a subordinate codeblock to his parent.

+--------------------+------------------+
| **Default Value**  | n/a              |
+--------------------+------------------+
| **Allowed values** | Any decoder name |
+--------------------+------------------+

Example:

Assign the decoder which father it belongs:

  .. code-block:: xml
    
    <decoder name="decoder_junior">
      <parent>decoder_father</parent>
      ...
    </decoder>

accumulate
^^^^^^^^^^^

Allow Wazuh to track events over multiple log messages based on a decoded id.

.. note::

   Requires a regex populating the id field.

+--------------------+--------------------+
| **Example of use** | <accumulate />     |
+--------------------+--------------------+

program_name
^^^^^^^^^^^^^

It defines the name of the program with which the decoder is associated.

+--------------------+--------------------------------------------------------------------+
| **Default Value**  | n/a                                                                |
+--------------------+--------------------------------------------------------------------+
| **Allowed values** | Any `sregex expression <regex.html#os-match-or-sregex-syntax>`_    |
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

It attempts to find a match within the log for the string defined.

+--------------------+--------------------------------------------------------------------+
| **Default Value**  | n/a                                                                |
+--------------------+--------------------------------------------------------------------+
| **Allowed values** | Any `sregex expression <regex.html#os-match-or-sregex-syntax>`_    |
+--------------------+--------------------------------------------------------------------+

The attribute below is optional, it allows to discard some of the content of the entry.

+--------------------+--------------------+
| Attribute          | Value              |
+====================+====================+
| **offset**         | after_regex        |
+--------------------+--------------------+

regex
^^^^^^^

**Regular expressions** or ``regex`` are sequences of characters that define a pattern.
Decoders use them to find words or other patterns into the rules.

An example is this regex that matches any numeral:

  ..code-block:: xml
    <regex> [+-]?(\d+(\.\d+)?|\.\d+)([eE][+-]?\d+)? </regex>


+--------------------+--------------------------------------------------------------------+
| **Default Value**  | n/a                                                                |
+--------------------+--------------------------------------------------------------------+
| **Allowed values** | Any `regex expression <regex.html#os-regex-or-regex-syntax>`_      |
+--------------------+--------------------------------------------------------------------+

The attribute below is optional, it allows to discard some of the content of the entry.

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

Show when an user executed the sudo command for the first time:

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

It defines what the parenthesis groups contain and the order in which they were received.

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

Allows to set the name of the child decoder from the name attribute instead of using the name of the parent decoder.

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

location
^^^^^^^^

Points the source where the event has been readed, like a log file or an agent.

+--------------------+-------------------------------------------------------------------------+
| **Default Value**  | string                                                                  |
+--------------------+-------------------------------------------------------------------------+
| **Allowed values** | File path (`/var/log/syslog`)                                           |
+                    +-------------------------------------------------------------------------+
|                    | An agent (`(ubuntu)->192.168.1.22`)                                     |
+--------------------+-------------------------------------------------------------------------+

Example:

  .. code-block:: xml 
    
    <decoder name="home_decoder">
      <location> /home/user </location>
      ...
    </decoder>

Only filters the events related to the path ``/home/user``.

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
