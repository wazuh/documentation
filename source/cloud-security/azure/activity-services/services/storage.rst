.. Copyright (C) 2015, Wazuh, Inc.

.. meta::
  :description: Azure Storage refers to the Microsoft Azure cloud storage solution. Learn how to use Azure Storage with Wazuh in this section of our documentation.

.. _azure_storage:

Using Azure Storage
===================

`Azure Storage <https://docs.microsoft.com/en-us/azure/storage/common/storage-introduction>`_ refers to the Microsoft Azure cloud storage solution, a service that provides a massively scalable object store for data objects, a messaging store for reliable messaging, a file system service for the cloud, and a NoSQL store.

.. thumbnail:: /images/cloud-security/azure/storage-activity-log.png
    :title: Storage
    :align: center
    :width: 60%

As an alternative to the Azure Log Analytics REST API, Wazuh offers the possibility to access Azure Storage accounts in a simple way. The activity logs of the Microsoft Azure infrastructure can be exported to the storage accounts.

This section explains how to use the Azure portal to archive the Azure activity log in a storage account and how to configure the ``azure-logs`` module. A use case is included to show a practical example. 


Configuring the Activity log export
-----------------------------------

#. Click **Activity log** in the **Monitor** service menu. You can type ``activity`` in the search bar to find the option.

   .. thumbnail:: /images/cloud-security/azure/storage-activity-4.png
       :title: Storage
       :align: center
       :width: 80%

#. Click **Export Activity logs**.

   .. thumbnail:: /images/cloud-security/azure/storage-activity-1.png
       :title: Storage
       :align: center
       :width: 80%

#. Click **Add diagnostic setting**.

   .. thumbnail:: /images/cloud-security/azure/storage-activity-2.png
       :title: Storage
       :align: center
       :width: 80%

#. Configure the following settings and click **Save**.

   -  Tick **Administrative** checkbox.
   -  Tick the **Archive to a storage account** checkbox.
   -  Select your **Subscription**.
   -  Select your **Storage account**.

   .. thumbnail:: /images/cloud-security/azure/storage-activity-3.png
       :title: Storage
       :align: center
       :width: 80%

Azure Storage use case
----------------------

This is a basic example of how to monitor the activity of the infrastructure. A new user will be created, resulting in an Azure Activity Log that will be exported to Storage if the Activity Log export was configured successfully.

Creating a user
^^^^^^^^^^^^^^^

An easy way to test this configuration is to create a new user in Microsoft Entra ID. A few minutes after the creation of the user, a new log will be available in a container named **insights-logs-auditlogs** inside the Storage account specified when configuring the Activity log export.

.. thumbnail:: /images/cloud-security/azure/storage-new-user-1.png
    :title: Storage
    :align: center
    :width: 80%

.. thumbnail:: /images/cloud-security/azure/storage-new-user-2.png
    :title: Storage
    :align: center
    :width: 80%

Wazuh configuration
^^^^^^^^^^^^^^^^^^^

Proceed to configure the ``azure-logs`` module in the local configuration (``ossec.conf``). It is important to set the **account_name** and **account_key** of the Storage account to authenticate. This information can be found in the **Access keys** section of **Storage accounts**. Check the :doc:`credentials </cloud-security/azure/activity-services/prerequisites/credentials>` reference for more information about the different authentication options available.

.. thumbnail:: /images/cloud-security/azure/account-credentials.png
    :title: Storage
    :align: center
    :width: 80%

Applying the following configuration, the integration will be executed every day using a credentials file for authentication. The ``insights-logs-auditlogs`` container content will be processed, downloading every blob available with the ``.json`` extension from the last ``24 hours``. The content for these blobs is expected to be in ``json_inline`` format.

.. code-block:: xml

    <wodle name="azure-logs">

        <disabled>no</disabled>
        <interval>1d</interval>
        <run_on_start>yes</run_on_start>

        <storage>

                <auth_path>/home/manager/Azure/storage_auth.txt</auth_path>
                <tag>azure-activity</tag>

                <container name="insights-logs-auditlogs">
                    <blobs>.json</blobs>
                    <content_type>json_inline</content_type>
                    <time_offset>24h</time_offset>
                </container>

        </storage>
    </wodle>

Check the :doc:`Azure module </user-manual/reference/ossec-conf/wodle-azure-logs>` reference page to learn more about the parameters available and how to use them.

Wazuh rules
^^^^^^^^^^^

Thanks to the following rules, already included in the default Wazuh ruleset, it is possible to monitor the infrastructure activity and obtain related alerts:

.. code-block:: xml

    <rule id="87803" level="3">
        <decoded_as>json</decoded_as>
        <field name="azure_tag">azure-storage</field>
        <description>Azure: Storage</description>
    </rule>

    <rule id="87813" level="3">
        <if_sid>87803</if_sid>
        <field name="operationName">\.+</field>
        <description>Azure: Storage: $(OperationName)</description>
    </rule>


Alert visualization
^^^^^^^^^^^^^^^^^^^

Once the Wazuh configuration is set and the ``azure-logs`` module is running using the previous configuration, the event from the user creation example exported to Storage will be processed. The results can be checked in the Wazuh dashboard. 

.. thumbnail:: /images/cloud-security/azure/storage-kibana.png
    :title: Storage
    :align: center
    :width: 80%