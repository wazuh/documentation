.. Copyright (C) 2015, Wazuh, Inc.

.. _wazuh_dashboard_config_file:

Configuration file
==================

The Wazuh dashboard includes a configuration file located at ``/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml`` where you can define custom values for several options. This section describes all the settings available in this file.

If you are using the Wazuh Kibana plugin, you can find this configuration file at ``/usr/share/kibana/data/wazuh/config/wazuh.yml``. 

The configuration file shows the default values for all of the possible options. You can edit the file, uncomment any of them and apply the desired values. You can also edit these settings from the Wazuh dashboard in *Settings > Configuration*.

The configuration file reference is organized by sections:

.. contents::
   :local:
   :depth: 2
   :backlinks: none

Basic options
-------------

hosts
^^^^^

Defines the list of APIs to connect with your Wazuh managers.

.. code-block:: yaml

    hosts:
        - <id>:
            url: http(s)://<url>
            port: <port>
            username: <username>
            password: <password>

.. note::

    It is required to specify at least one host.

This is an example of a multi-host configuration:

.. code-block:: yaml

    hosts:
        - wazuh_prod:
            url: https://wazuh.com
            port: 55000
            username: wazuh-wui
            password: secret_password
            run_as: false
        - wazuh_test:
            url: https://localhost
            port: 55000
            username: wazuh-wui
            password: wazuh-wui
            run_as: false


pattern
^^^^^^^

Default index pattern to use on the app. If there's no valid index patterns on Elasticsearch, the app will automatically create one with the name indicated in this option.

+--------------------+-------------------------+
| **Default value**  | wazuh-alerts-*          |
+--------------------+-------------------------+
| **Allowed values** | Any valid index pattern |
+--------------------+-------------------------+

timeout
^^^^^^^

Defines the maximum time the app will wait for an API response when making requests to it. It will be ignored if the value is set under 1500 milliseconds.

+--------------------+-------------------------------+
| **Default value**  | 20000 (milliseconds)          |
+--------------------+-------------------------------+
| **Allowed values** | Any number starting from 1500 |
+--------------------+-------------------------------+

ip.selector
^^^^^^^^^^^

Defines if the user is allowed to change the selected index pattern directly from the top menu bar.

+--------------------+------------+
| **Default value**  | true       |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

ip.ignore
^^^^^^^^^

Disable certain index pattern names from being available in index pattern selector from the Wazuh dashboard. An empty list (the default value) won't ignore any valid index pattern.

+--------------------+---------------------------------------------+
| **Default value**  | []                                          |
+--------------------+---------------------------------------------+
| **Allowed values** | Array of strings. Eg: ["wazuh-archives-\*"] |
+--------------------+---------------------------------------------+

logs.level
^^^^^^^^^^

Set the logging level for the Wazuh dashboard log files.

+--------------------+------------+
| **Default value**  | info       |
+--------------------+------------+
| **Allowed values** | info,debug |
+--------------------+------------+

hideManagerAlerts
^^^^^^^^^^^^^^^^^

Hide the manager alerts in the dashboard visualizations.

+--------------------+------------+
| **Default value**  | false      |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

Monitoring
----------

wazuh.monitoring.enabled
^^^^^^^^^^^^^^^^^^^^^^^^

Enable or disable the ``wazuh-monitoring`` index creation and/or visualization:

- When the value is set to ``true``, the app will show the *Agents status* visualization and will insert monitoring-related data.
- When the value is set to ``false``, the app won't show the visualization and won't insert monitoring-related data.
- When the value is set to ``worker``, the app will show the visualization, but won't insert monitoring-related data.

+--------------------+-------------------+
| **Default value**  | true              |
+--------------------+-------------------+
| **Allowed values** | true,false,worker |
+--------------------+-------------------+

wazuh.monitoring.frequency
^^^^^^^^^^^^^^^^^^^^^^^^^^

Define in seconds the frequency of API requests to get the state of the agents to create a new document in the `wazuh-monitoring` index with this data.

+--------------------+-----------------------------+
| **Default value**  | 900 (seconds)               |
+--------------------+-----------------------------+
| **Allowed values** | Any number starting from 60 |
+--------------------+-----------------------------+

.. warning::

    Although the minimum value can be ``60``, we recommend adjusting it to at least ``300`` seconds to avoid overloading issues due to the excessive creation of documents into the index.

wazuh.monitoring.pattern
^^^^^^^^^^^^^^^^^^^^^^^^

Default Wazuh monitoring index pattern to use for the app. This setting does not remove any existing patterns or templates, it just updates the app to add the new ones.

+--------------------+-------------------------+
| **Default value**  | wazuh-monitoring-*      |
+--------------------+-------------------------+
| **Allowed values** | Any valid index pattern |
+--------------------+-------------------------+

wazuh.monitoring.creation
^^^^^^^^^^^^^^^^^^^^^^^^^

Configure wazuh-monitoring-* indices custom creation interval.

+--------------------+------------------------------------------------+
| **Default value**  | w (weekly)                                     |
+--------------------+------------------------------------------------+
| **Allowed values** | h (hourly), d (daily), w (weekly), m (monthly) |
+--------------------+------------------------------------------------+

Checks
------

checks.pattern
^^^^^^^^^^^^^^

Enable or disable the index pattern health check when opening the app.

+--------------------+------------+
| **Default value**  | true       |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

checks.template
^^^^^^^^^^^^^^^

Enable or disable the template health check when opening the app.

+--------------------+------------+
| **Default value**  | true       |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

checks.api
^^^^^^^^^^

Enable or disable the Wazuh API health check when opening the app.

+--------------------+------------+
| **Default value**  | true       |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

checks.setup
^^^^^^^^^^^^

Enable or disable the setup health check when opening the app.

+--------------------+------------+
| **Default value**  | true       |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

checks.fields
^^^^^^^^^^^^^

Enable or disable the known fields health check when opening the app.

+--------------------+------------+
| **Default value**  | true       |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

checks.metaFields
^^^^^^^^^^^^^^^^^

Enable or disable the metaFields health check when opening the app.

+--------------------+------------+
| **Default value**  | true       |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

checks.timeFilter
^^^^^^^^^^^^^^^^^

Enable or disable the timeFilter health check when opening the app.

+--------------------+------------+
| **Default value**  | true       |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

checks.maxBuckets
^^^^^^^^^^^^^^^^^

Enable or disable the maxBuckets health check when opening the app.

+--------------------+------------+
| **Default value**  | true       |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

Extensions
----------

.. note::

    These options are only applied for newly inserted APIs on the *Settings* tab, not for the existing ones.

extensions.pci
^^^^^^^^^^^^^^

Enable or disable the PCI DSS tab on *Overview* and *Agents*.

+--------------------+------------+
| **Default value**  | true       |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

extensions.gdpr
^^^^^^^^^^^^^^^

Enable or disable the GDPR tab on *Overview* and *Agents*.

+--------------------+------------+
| **Default value**  | true       |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

extensions.hipaa
^^^^^^^^^^^^^^^^

Enable or disable the HIPAA tab on *Overview* and *Agents*.

+--------------------+------------+
| **Default value**  | true       |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

extensions.nist
^^^^^^^^^^^^^^^

Enable or disable the NIST tab on *Overview* and *Agents*.

+--------------------+------------+
| **Default value**  | true       |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

extensions.tsc
^^^^^^^^^^^^^^

Enable or disable the TSC tab on *Overview* and *Agents*.

+--------------------+------------+
| **Default value**  | true       |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

extensions.audit
^^^^^^^^^^^^^^^^

Enable or disable the Audit tab on *Overview* and *Agents*.

+--------------------+------------+
| **Default value**  | true       |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

extensions.oscap
^^^^^^^^^^^^^^^^

Enable or disable the OSCAP tab on *Overview* and *Agents*.

+--------------------+------------+
| **Default value**  | false      |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

extensions.ciscat
^^^^^^^^^^^^^^^^^

Enable or disable the CIS-CAT tab on *Overview* and *Agents*.

+--------------------+------------+
| **Default value**  | false      |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

extensions.aws
^^^^^^^^^^^^^^

Enable or disable the Amazon (AWS) tab on *Overview* and *Agents*.

+--------------------+------------+
| **Default value**  | false      |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

extensions.gcp
^^^^^^^^^^^^^^

Enable or disable the GCP tab on *Overview* and *Agents*.

+--------------------+------------+
| **Default value**  | false      |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

extensions.virustotal
^^^^^^^^^^^^^^^^^^^^^

Enable or disable the VirusTotal tab on *Overview* and *Agents*.

+--------------------+------------+
| **Default value**  | false      |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

extensions.osquery
^^^^^^^^^^^^^^^^^^

Enable or disable the Osquery tab on *Overview* and *Agents*.

+--------------------+------------+
| **Default value**  | false      |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

extensions.docker
^^^^^^^^^^^^^^^^^

Enable or disable the Docker listener tab on *Overview* and *Agents*.

+--------------------+------------+
| **Default value**  | false      |
+--------------------+------------+
| **Allowed values** | true,false |
+--------------------+------------+

Advanced index options
----------------------

.. warning::

    These options are only valid if they're modified before starting Wazuh dashboard for the very first time.

    You can read more about configuring the shards and replicas in the :ref:`shards_and_replicas` section.


wazuh.monitoring.shards
^^^^^^^^^^^^^^^^^^^^^^^

Define the number of shards to use for the ``wazuh-monitoring-*`` indices.

+--------------------+----------------------------+
| **Default value**  | 1                          |
+--------------------+----------------------------+
| **Allowed values** | Any number starting from 1 |
+--------------------+----------------------------+

wazuh.monitoring.replicas
^^^^^^^^^^^^^^^^^^^^^^^^^

Define the number of replicas to use for the ``wazuh-monitoring-*`` indices.

+--------------------+----------------------------+
| **Default value**  | 0                          |
+--------------------+----------------------------+
| **Allowed values** | Any number starting from 0 |
+--------------------+----------------------------+

Unauthorized roles
------------------

disabled_roles
^^^^^^^^^^^^^^

Disable Wazuh for the Elasticsearch / OpenSearch roles defined here.

.. code-block:: yaml

    disabled_roles: 
        - wazuh_disabled

Sample alerts
-------------

alerts.sample.prefix
^^^^^^^^^^^^^^^^^^^^

Define the index name prefix of sample alerts. It must match the template used by the index pattern to avoid unknown fields in dashboards.

+--------------------+----------------------------+
| **Default value**  | wazuh-alerts-4.x-          |
+--------------------+----------------------------+
| **Allowed values** | Any valid index pattern    |
+--------------------+----------------------------+

Enrollment DNS
--------------

enrollment.dns
^^^^^^^^^^^^^^

Specifies the Wazuh registration server, used for the agent enrollment.

+--------------------+----------------------------+
| **Default value**  | ''                         |
+--------------------+----------------------------+
| **Allowed values** | Any string                 |
+--------------------+----------------------------+

enrollment.password
^^^^^^^^^^^^^^^^^^^

Specifies the password used to authenticate during the agent enrollment.

+--------------------+----------------------------+
| **Default value**  | ''                         |
+--------------------+----------------------------+
| **Allowed values** | Any string                 |
+--------------------+----------------------------+

Cron
----

cron.prefix
^^^^^^^^^^^

Define the index prefix of predefined jobs.

+--------------------+----------------------------+
| **Default value**  | ''                         |
+--------------------+----------------------------+
| **Allowed values** | Any string                 |
+--------------------+----------------------------+

cron.statistics.status
^^^^^^^^^^^^^^^^^^^^^^

Enable or disable the statistics tasks.

+--------------------+----------------------------+
| **Default value**  | true                       |
+--------------------+----------------------------+
| **Allowed values** | true,false                 |
+--------------------+----------------------------+

cron.statistics.apis
^^^^^^^^^^^^^^^^^^^^

Enter the ID of the hosts you want to save data from, leave this empty to run the task on every host.

+--------------------+----------------------------+
| **Default value**  | []                         |
+--------------------+----------------------------+
| **Allowed values** | Array of APIs              |
+--------------------+----------------------------+

cron.statistics.interval
^^^^^^^^^^^^^^^^^^^^^^^^

Define the frequency of task execution using cron schedule expressions.

+--------------------+----------------------------+
| **Default value**  | ``0 */5 * * * *``          |
+--------------------+----------------------------+
| **Allowed values** | Any cron expressions       |
+--------------------+----------------------------+

cron.statistics.index.name
^^^^^^^^^^^^^^^^^^^^^^^^^^

Define the name of the index in which the documents will be saved.

+--------------------+----------------------------+
| **Default value**  | statistics                 |
+--------------------+----------------------------+
| **Allowed values** | Any valid index pattern    |
+--------------------+----------------------------+

cron.statistics.index.creation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Define the interval in which a new index will be created.

+--------------------+-------------------------------------------------+
| **Default value**  | w                                               |
+--------------------+-------------------------------------------------+
| **Allowed values** | h (hourly), d (daily), w (weekly), m (monthly)  |
+--------------------+-------------------------------------------------+

cron.statistics.shards
^^^^^^^^^^^^^^^^^^^^^^

Define the number of shards to use for the statistics indices.

+--------------------+----------------------------+
| **Default value**  | 1                          |
+--------------------+----------------------------+
| **Allowed values** | Any number starting from 1 |
+--------------------+----------------------------+

cron.statistics.replicas
^^^^^^^^^^^^^^^^^^^^^^^^

Define the number of replicas to use for the statistics indices.

+--------------------+----------------------------+
| **Default value**  | 0                          |
+--------------------+----------------------------+
| **Allowed values** | Any number starting from 0 |
+--------------------+----------------------------+

Logo customization
------------------

customization.logo.app
^^^^^^^^^^^^^^^^^^^^^^

Define the name of the app logo saved in the path ``/plugins/wazuh/public/assets/``.

+--------------------+----------------------------+
| **Default value**  | ''                         |
+--------------------+----------------------------+
| **Allowed values** | Any string                 |
+--------------------+----------------------------+

customization.logo.sidebar
^^^^^^^^^^^^^^^^^^^^^^^^^^

Define the name of the sidebar logo saved in the path ``/plugins/wazuh/public/assets/``.

+--------------------+----------------------------+
| **Default value**  | ''                         |
+--------------------+----------------------------+
| **Allowed values** | Any string                 |
+--------------------+----------------------------+

customization.logo.healthcheck
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Define the name of the health check logo saved in the path ``/plugins/wazuh/public/assets/``.

+--------------------+----------------------------+
| **Default value**  | ''                         |
+--------------------+----------------------------+
| **Allowed values** | Any string                 |
+--------------------+----------------------------+

customization.logo.reports
^^^^^^^^^^^^^^^^^^^^^^^^^^

Define the name of the reports logo saved in the path ``/plugins/wazuh/public/assets/``.

+--------------------+----------------------------+
| **Default value**  |''                          |
+--------------------+----------------------------+
| **Allowed values** | Any string                 |
+--------------------+----------------------------+


Example
-------

This is an example of the wazuh.yml configuration:

.. code-block:: yaml
    
    #Basic options

    hosts:
        - env-1:
            url: https://env-1.example
            port: 55000
            username: wazuh-wui
            password: wazuh-wui
            run_as: true
        - env-2:
            url: https://env-2.example
            port: 55000
            username: wazuh-wui
            password: wazuh-wui
            run_as: true

    pattern: 'wazuh-alerts-*'
    timeout: 20000
    ip.selector: true
    ip.ignore: []
    logs.level: info
    hideManagerAlerts: true

    #Monitoring

    wazuh.monitoring.enabled: true
    wazuh.monitoring.frequency: 900
    wazuh.monitoring.pattern: wazuh-monitoring-*
    wazuh.monitoring.creation: w

    #Checks

    checks.pattern : true
    checks.template: true
    checks.fields  : true
    checks.api     : true
    checks.setup   : true
    checks.metaFields: true
    checks.timeFilter: true
    checks.maxBuckets: true

    #Extensions

    extensions.pci       : true
    extensions.gdpr      : true
    extensions.hipaa     : true
    extensions.nist      : true
    extensions.tsc       : true
    extensions.audit     : true
    extensions.oscap     : false
    extensions.ciscat    : false
    extensions.aws       : false
    extensions.gcp       : false
    extensions.virustotal: false
    extensions.osquery   : false
    extensions.docker    : false

    #Advanced index options

    wazuh.monitoring.shards: 1
    wazuh.monitoring.replicas: 0    

    #Logo customization

    customization.logo.app: ''
    customization.logo.sidebar: ''
    customization.logo.healthcheck: ''
    customization.logo.reports: ''

    #Unauthorized roles

    disabled_roles: 
        - wazuh_disabled

    #Sample alerts

    alerts.sample.prefix: wazuh-alerts-4.x-

    #Cron

    cron.prefix: wazuh
    cron.statistics.status: true
    cron.statistics.apis: []
    cron.statistics.interval: 0 */5 * * * *
    cron.statistics.index.name: statistics
    cron.statistics.index.creation: w
    cron.statistics.shards: 1
    cron.statistics.replicas: 0

    #Enrollment DNS

    enrollment.dns: ''
    enrollment.password: ''