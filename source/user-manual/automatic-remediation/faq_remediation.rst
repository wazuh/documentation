.. _faq_remediation:

Faq
==========================

1. `Can I use a custom script?`_
2. `Can I configure active response to only one host?`_
3. `Can active response remove the action after a time?`_

``Can I use a custom script?``
------------------------------
Yes. You can create your own script and configure the command and the active response to use it.

``Can I configure active response to only one host?``
-----------------------------------------------------
Yes, using the ``location`` option. More info: :ref:`Active Response options <reference_ossec_active_response>`

``Can active response remove the action after a time?``
-------------------------------------------------------
Yes, using ``timeout_allowed`` option  on the command and ``timeout`` on active response. :ref:`Example <how_to_remediation>`
