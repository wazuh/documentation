.. Copyright (C) 2015, Wazuh, Inc.

.. meta::
  :description: Wazuh provides two types of storage for your data: indexed and archive. Learn more about the archive data in this section. 

.. _cloud_archive_data_access:

Access
======

To access your archive data, you need an AWS token that grants permission on the AWS S3 bucket of your environment. This token can be generated using the Wazuh Cloud API.

   .. note::
      See the :doc:`Wazuh Cloud CLI </cloud-service/cli/index>` section to learn how to list and download your archive data automatically.


The following example describes the steps to follow to list the files of your archive data:


1. Before your start using the Wazuh Cloud API, you need an API key. To generate your API key, see the :ref:`Authentication <cloud_apis_auth>` section.

2. Use the ``POST /storage/token`` endpoint of the :cloud-api-ref:`Wazuh Cloud API <tag/storage>` to get the AWS token and access the archive data of a specific environment. In this example, we generate an AWS token valid for 3600 seconds for environment `0123456789ab`.

   .. code-block::

      curl -XPOST https://api.cloud.wazuh.com/v2/storage/token -H "x-api-key: <YOUR_API_KEY>" -H "Content-Type: application/json" --data '
      {
         "environment_cloud_id": "0123456789ab",
         "token_expiration": "3600"
      }'

   .. code-block:: console
      :class: output

      {
         "environment_cloud_id": "0123456789ab",
         "aws": {
            "s3_path": "wazuh-cloud-cold-us-east-1/0123456789ab",
            "region": "us-east-1",
            "credentials": {
               "access_key_id": "mUdT2dBjlHd...Gh7Ni1yZKR5If",
               "secret_access_key": "qEzCk63a224...5aB+e4fC1BR0G",
               "session_token": "MRg3t7HIuoA...4o4BXSAcPfUD8",
               "expires_in": 3600
            }
         }
      }

3. Using the AWS-CLI tool to list the files, add the token to the AWS credentials file ``~/.aws/credentials``.

   .. code-block:: console
      
      [wazuh_cloud_storage]
      aws_access_key_id = mUdT2dBjlHd...Gh7Ni1yZKR5If
      aws_secret_access_key = qEzCk63a224...5aB+e4fC1BR0G
      aws_session_token = MRg3t7HIuoA...4o4BXSAcPfUD8

4. Run the following command to list your files.

   .. code-block:: console
      
      $ aws --profile wazuh_cloud_storage --region us-east-1 s3 ls wazuh-cloud-cold-us-east-1/0123456789ab

You now have access to your archive data.
