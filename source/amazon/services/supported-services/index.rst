.. Copyright (C) 2019 Wazuh, Inc.

.. _amazon_supported_services:

Supported services
==================

.. meta::
  :description: Supported services

All the services except ``Inspector`` get the data from log files stored in an ``S3`` bucket. These services store their data into log files which are configured inside ``<bucket type='TYPE'> </bucket>`` tags, while ``Inspector`` service is configured inside ``<service type='inspector'> </service>`` tags.

The next table contains the more relevant information about configuring each service in ``ossec.conf``:

+--------------------------------------------------+-----------------------+---------------+---------------------------------------------------------------------------------------------+
| **Service**                                      | **Configuration tag** | **Type**      | **Path to logs**                                                                            |
+--------------------------------------------------+-----------------------+---------------+---------------------------------------------------------------------------------------------+
| :ref:`CloudTrail <amazon_cloudtrail>`            | bucket                | cloudtrail    | <bucket_name>/<prefix>/AWSLogs/<account_id>/CloudTrail/<region>/<year>/<month>/<day>        |
+--------------------------------------------------+-----------------------+---------------+---------------------------------------------------------------------------------------------+
| :ref:`VPC <amazon_vpc>`                          | bucket                | vpcflow       | <bucket_name>/<prefix>/AWSLogs/<account_id>/vpcflowlogs/<region>/<year>/<month>/<day>       |
+--------------------------------------------------+-----------------------+---------------+---------------------------------------------------------------------------------------------+
| :ref:`Config <amazon_config>`                    | bucket                | config        | <bucket_name>/<prefix>/AWSLogs/<account_id>/Config/<region>/<year>/<month>/<day>            |
+--------------------------------------------------+-----------------------+---------------+---------------------------------------------------------------------------------------------+
| :ref:`KMS <amazon_kms>`                          | bucket                | custom        | <bucket_name>/<prefix>/<year>/<month>/<day>                                                 |
+--------------------------------------------------+-----------------------+---------------+---------------------------------------------------------------------------------------------+
| :ref:`Macie <amazon_macie>`                      | bucket                | custom        | <bucket_name>/<prefix>/<year>/<month>/<day>                                                 |
+--------------------------------------------------+-----------------------+---------------+---------------------------------------------------------------------------------------------+
| :ref:`Trusted Advisor <amazon_trusted_advisor>`  | bucket                | custom        | <bucket_name>/<prefix>/<year>/<month>/<day>                                                 |
+--------------------------------------------------+-----------------------+---------------+---------------------------------------------------------------------------------------------+
| :ref:`GuardDuty <amazon_guardduty>`              | bucket                | guardduty     | <bucket_name>/<prefix>/<year>/<month>/<day>/<hh>                                            |
+--------------------------------------------------+-----------------------+---------------+---------------------------------------------------------------------------------------------+
| :ref:`Inspector <amazon_inspector>`              | service               | inspector     |                                                                                             |
+--------------------------------------------------+-----------------------+---------------+---------------------------------------------------------------------------------------------+

.. toctree::
    :maxdepth: 1
    :hidden:

    cloudtrail
    vpc
    config
    kms
    macie
    trusted-advisor
    guardduty
    inspector
