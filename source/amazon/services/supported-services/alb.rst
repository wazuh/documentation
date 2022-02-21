.. Copyright (C) 2022 Wazuh, Inc.

.. meta::
  :description: AWS Application Load Balancer is a service that distributes incoming application traffic across multiple targets. Learn how to configure and monitor it with Wazuh.

.. _amazon_alb:

Amazon ALB
==========

`Application Load Balancers <https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html>`_ (Amazon ALB) Elastic Load Balancing automatically distributes the incoming traffic across multiple targets, such as EC2 instances, containers, and IP addresses, in one or more Availability Zones. It monitors the health of its registered targets and routes traffic only to the healthy targets. Users can select the type of load balancer that best suits their needs. An Application Load Balancer functions at the application layer, the seventh layer of the Open Systems Interconnection (OSI) model. After the load balancer receives a request, it evaluates the listener rules in priority order to determine which rule to apply, and then selects a target from the target group for the rule action.

Amazon configuration
--------------------

#. Select an existing S3 Bucket or :ref:`create a new one. <S3_bucket>`

#. Go to Services > Compute > EC2:

    .. thumbnail:: ../../../images/aws/aws-create-vpc-1.png
      :align: center
      :width: 70%

#. Go to Load Balancing > Load Balancers on the left menu. Create a new load balancer or select one or more load balancers and select *Edit attributes* on the *Actions* menu:

    .. thumbnail:: ../../../images/aws/aws-create-elb-1.png
      :align: center
      :width: 70%

#. In this tab we will define our S3 and the path where the logs will be stored:

    .. thumbnail:: ../../../images/aws/aws-create-elb-2.png
      :align: center
      :width: 70%

    .. note::
      To enable access logs for ALB (Application Load Balancers), check the following link:

        * `Application Load Balancer. <https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html>`_


Wazuh configuration
-------------------

#. Open the Wazuh configuration file (``/var/ossec/etc/ossec.conf``) and add the following block for ALB:

    .. code-block:: xml

      <wodle name="aws-s3">
        <disabled>no</disabled>
        <interval>10m</interval>
        <run_on_start>yes</run_on_start>
        <skip_on_error>yes</skip_on_error>
        <bucket type="alb">
          <name>wazuh-aws-wodle</name>
          <path>ALB</path>
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
