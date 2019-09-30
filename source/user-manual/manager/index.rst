.. _user_manual_manager:

Wazuh server administration
===========================

Wazuh manager is the system that analyzes the data received from all the agents, triggering alerts when an event matches a rule for example: intrusion detected, file changed, configuration not compliant with policy, possible rootkit, etc. It is also an agent, so it has all the features that an agent has. Also, the manager can forward the alerts it triggered through syslog, emails or integration with external APIs.

.. topic:: Contents

    .. toctree::
        :maxdepth: 2

        remote-service
        alert-threshold
        manual-integration
        manual-syslog-output
        automatic-reports
        manual-email-report/index
