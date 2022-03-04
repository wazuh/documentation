.. Copyright (C) 2022 Wazuh, Inc.

.. meta::
  :description: AWS Config is a service that records the configuration of AWS resources easing auditing tasks. Learn how to configure and monitor it with Wazuh.

.. _amazon_config:

AWS Config
==========

`AWS Config <https://aws.amazon.com/config/>`_ is a service that enables you to assess, audit, and evaluate the configurations of your AWS resources. Config continuously monitors and records your AWS resource configurations and allows you to automate the evaluation of recorded configurations against desired configurations. With Config, you can review changes in configurations and relationships between AWS resources, dive into detailed resource configuration histories, and determine your overall compliance against the configurations specified in your internal guidelines. This enables you to simplify compliance auditing, security analysis, change management, and operational troubleshooting.

Amazon configuration
--------------------

#. On the `AWS Config page, <https://console.aws.amazon.com/config/>`_ go to *Settings*.

#. Here, choose the **Resource types to record** (specify the AWS resource types you want AWS Config to record):

    - All resources
    - Specific types

    .. note::
      For more information about these options, see `Selecting Which Resources AWS Config Records. <https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html>`_

#. Select an existing S3 Bucket or :ref:`create a new one. <S3_bucket>`

    .. thumbnail:: ../../../images/aws/aws-create-config-1.png
      :align: center
      :width: 100%

    After these steps, it is necessary to configure the rules.

#. Go to Services > Management Tools > CloudWatch:

    .. thumbnail:: ../../../images/aws/aws-create-firehose-12.png
      :align: center
      :width: 100%

#. Select Rules on the left menu and click on the *Create* rule button:

    .. thumbnail:: ../../../images/aws/aws-create-firehose-13.png
      :align: center
      :width: 100%

#. Select which service do you want to get logs from using the Service name slider, then, click on the Add target button and add the previously created Firehose delivery stream there. Also, create a new role to access the delivery stream:

    .. thumbnail:: ../../../images/aws/aws-create-firehose-14.png
      :align: center
      :width: 100%

#. Give the rule some name and click on the *Create* rule button:

    .. thumbnail:: ../../../images/aws/aws-create-firehose-15.png
      :align: center
      :width: 100%

#. Once the rule is created, data will start to be sent to the previously created S3 bucket. Remember to first enable the service you want to monitor, otherwise you won't get any data.

Policy configuration
++++++++++++++++++++

.. include:: /_templates/cloud/amazon/create_policy.rst
.. include:: /_templates/cloud/amazon/bucket_policies.rst
.. include:: /_templates/cloud/amazon/attach_policy.rst

Wazuh configuration
-------------------

#. Open the Wazuh configuration file (``/var/ossec/etc/ossec.conf``) and add the following block:

    .. code-block:: xml

      <wodle name="aws-s3">
        <disabled>no</disabled>
        <interval>10m</interval>
        <run_on_start>yes</run_on_start>
        <skip_on_error>yes</skip_on_error>
        <bucket type="config">
          <name>wazuh-aws-wodle</name>
          <path>config</path>
          <aws_profile>default</aws_profile>
        </bucket>
      </wodle>

    .. note::
      Check the :ref:`AWS S3 module <wodle_s3>` reference manual to learn more about each setting.

#. Restart Wazuh in order to apply the changes:

    * If you're configuring a Wazuh manager:

      a. For Systemd:

      .. code-block:: console

        # systemctl restart wazuh-manager

      b. For SysV Init:

      .. code-block:: console

        # service wazuh-manager restart

    * If you're configuring a Wazuh agent:

      a. For Systemd:

      .. code-block:: console

        # systemctl restart wazuh-agent

      b. For SysV Init:

      .. code-block:: console

        # service wazuh-agent restart
