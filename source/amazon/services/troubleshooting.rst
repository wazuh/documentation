.. Copyright (C) 2019 Wazuh, Inc.

.. _amazon_troubleshooting:

Troubleshooting
===============

.. meta::
  :description: Frequently asked questions about the Wazuh module for Amazon.

The below information is intended to assist in troubleshooting issues.


Testing the integration
-----------------------

After configuring the module successfully users can expect to see the following log messages in their agent log file: ``/var/ossec/logs/ossec.log``

1. Module starting:

    .. code-block:: console

        2019/10/28 13:58:10 wazuh-modulesd:aws-s3[8184] wm_aws.c:48 at wm_aws_main(): INFO: Module AWS started


2. Scheduled scan:

    .. code-block:: console

        2019/10/28 13:58:10 wazuh-modulesd:aws-s3: INFO: Starting fetching of logs.
        2019/10/28 13:38:11 wazuh-modulesd:aws-s3: INFO: Fetching logs finished.


Common errors
-------------

1. Errors in ``ossec.log``

    When an error occurs when trying to collect and parse logs for an AWS service, the ``ossec.log`` will output an error such as below:

    The number is the AWS Account ID provided for the CloudTrail, and the name in the parenthesis is the AWS Account Alias (if provided).

    .. code-block:: console

        2019/10/28 13:58:11 wazuh-modulesd:aws-s3: WARNING: Bucket: wazuh-cloudtrail  -  Returned exit code 3
        2019/10/28 13:58:11 wazuh-modulesd:aws-s3: WARNING: Bucket: wazuh-cloudtrail  -  Invalid credentials to access S3 Bucket

    The exit codes and their possible remediations are the next:


    +-----------+------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Code**  | **Description**                                      | **Possible remediation**                                                                                                                                      |
    +-----------+------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | 1         | Unknown error                                        | Programming error. Please, open an issue in the `Wazuh GitHub repository <https://github.com/wazuh/wazuh/issues/new/choose>`_ with the trace of the error     |
    +-----------+------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | 2         | Error parsing configuration (bucket name, keys, etc) | Check the wodle configuration in ``ossec.conf`` file                                                                                                          |
    +-----------+------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | 3         | Invalid credentials to access S3 bucket              | Ensure that your credentials are OK. :ref:`Credentials <amazon_credentials>` section may be useful                                                            |
    +-----------+------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | 4         | boto3 module missing                                 | Install ``boto3`` library. Visit :ref:`dependencies <amazon_dependencies>` section for getting more information                                               |
    +-----------+------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | 5         | Unexpected error accessing SQLite DB                 | Check that no more instances of the wodle are running at the same time                                                                                        |
    +-----------+------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | 6         | Unable to create SQLite DB                           | Ensure that the wodle has the right permissions in its directory                                                                                              |
    +-----------+------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | 7         | Unexpected error querying/working with objects in S3 | Check that no more instances of the wodle are running at the same time                                                                                        |
    +-----------+------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | 8         | Failed to decompress file                            | Only ``.gz`` and ``.zip`` compression formats are supported                                                                                                   |
    +-----------+------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | 9         | Failed to parse file                                 | Check the type of the bucket                                                                                                                                  |
    +-----------+------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | 10        | Failed to execute DB cleanup                         | Check that no more instances of the wodle are running at the same time                                                                                        |
    +-----------+------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | 11        | Unable to connect to Wazuh                           | Ensure that Wazuh is running                                                                                                                                  |
    +-----------+------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | 12        | SIGINT                                               | The module stopped due to an interrupt signal                                                                                                                 |
    +-----------+------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | 13        | Error sending message to Wazuh                       | Ensure that Wazuh is running                                                                                                                                  |
    +-----------+------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------+


2. Debugging configuration:

    If users are unable to determine the issues from the ``ossec.log``, users can run the modules in debug mode.  With Wazuh running, stop the moduled

    .. code-block:: console

        # pkill wazuh-modulesd

    Start wazuh-modulesd in the foreground in debug mode

    .. code-block:: console

        # /var/ossec/bin/wazuh-modulesd -fd

    +--------+-----------------------------------------------------------+
    | Debug  | Description                                               |
    +--------+-----------------------------------------------------------+
    | -fd    | Basic debug                                               |
    +--------+-----------------------------------------------------------+
    | -fdd   | Verbose debug                                             |
    +--------+-----------------------------------------------------------+
    | -fddd  | Extremely verbose debug (Warning: generates logs of msgs) |
    +--------+-----------------------------------------------------------+

    This will print debug data to the console and log.  The debug will also output the command that the wodle is using to execute the Python script for each service.  If a particular service is causing problems, this command can be manually executed, increasing the debug level from 1 (basic) to 3 (extremely verbose)

    .. code-block:: console

        # 2019/10/28 14:08:28 wazuh-modulesd:aws-s3[2557] wm_aws.c:409 at wm_aws_run_s3(): DEBUG: Launching S3 Command: /var/ossec/wodles/aws/aws-s3 --bucket wazuh-cloudtrail --access_key XXXXXXXX --secret_key XXXXXXXX --type cloudtrail --debug 2 --skip_on_error

3. Time interval is shorter than the time taken to pull log data:

    In this case a simple warning will be displayed. There is no impact in the event data fetching process and the module will keep running.

    .. code-block:: console

        # 2019/10/28 14:08:31 wazuh-modulesd:aws-s3[2557] wm_aws.c:409 at wm_aws_run_s3(): WARNING: Interval overtaken.

4. Wrong AWS service path:

    If users get any trouble related to "paths", check if the AWS files path is correct:

      **AWS Cloudtrail**

        <bucket_name>/<prefix>/AWSLogs/<account_id>/CloudTrail/<region>/<year>/<month>/<day>

      **AWS Config**

        <bucket_name>/<prefix>/AWSLogs/<account_id>/Config/<region>/<year>/<month>/<day>/ConfigHistory
        <bucket_name>/<prefix>/AWSLogs/<account_id>/Config/<region>/<year>/<month>/<day>/ConfigSnapshot

      **AWS Guardduty**

        <bucket_name>/<prefix>/<year>/<month>/<day>/<hh>

      **AWS Custom bucket**

        <bucket_name>/<prefix>/<year>/<month>/<day>

      **AWS VPC**

        <bucket_name>/<prefix>/AWSLogs/<account_id>/vpcflowlogs/<region>/<year>/<month>/<day>

      **Use case**

        AmazonS3/config/AWSLogs/1308927/Config/EU-West/2019/01/12/file.log

        AmazonFirstBucket/store/2019/01/9/logs.log
