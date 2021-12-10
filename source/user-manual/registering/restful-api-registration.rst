.. Copyright (C) 2021 Wazuh, Inc.

.. meta::
  :description: Check out how to register the Wazuh agents using the Wazuh API. This allows the Wazuh agent registration by running a single request from any host.
  
.. _restful-api-registration:

Registering the Wazuh agents using the Wazuh API
================================================

The Wazuh API allows the Wazuh agent registration by running a single request from any host. This request returns the Wazuh agent's registration key, which must be manually added to the Wazuh agent using ``manage_agents`` utility.

.. note:: Root user privileges are necessary to execute all the commands described below, and the Wazuh API must be accessible from the host on which the request is executed.

.. warning::

  Terminal history will keep the generated agent key when using the ``manage_agents`` utility. Consider disabling it beforehand, cleaning it afterward, or using another registration method.

Choose the tab corresponding to the Wazuh agent host operating system:

.. tabs::


  .. group-tab:: Linux/Unix host


    #. Open a terminal in the Wazuh agent's host as a ``root`` user. To add the Wazuh agent to the Wazuh manager and extract the registration key execute the following Wazuh API request :api-ref:`POST /agents <operation/api.controllers.agent_controller.add_agent>` and replacing the values in the angle brackets:

         .. code-block:: console

           # curl -k -X POST -d '{"name":"<agent_name>","ip":"<agent_IP>"}' "https://localhost:55000/agents?pretty=true" -H "Content-Type:application/json" -H "Authorization: Bearer $TOKEN"

         The output of the Wazuh API request returns the registration key:

         .. code-block:: none
                :class: output

                {
                    "error": 0,
                    "data": {
                        "id": "001",
                        "key": "MDAxIE5ld0FnZW50IDEwLjAuMC44IDM0MGQ1NjNkODQyNjcxMWIyYzUzZTE1MGIzYjEyYWVlMTU1ODgxMzVhNDE3MWQ1Y2IzZDY4M2Y0YjA0ZWVjYzM=",
                    },
                }

         More information about API credentials and HTTPS support can be found on :ref:`Wazuh API configuration<api_configuration>`.


    #. Import the registration key to the Wazuh agent using ``manage_agents`` utility. Replace the Wazuh agent's registration key:

         .. code-block:: console

          # /var/ossec/bin/manage_agents -i <key>

         An example output of the command looks as follows:

         .. code-block:: none
                :class: output

                Agent information:
                   ID:001
                   Name:agent_1
                   IP Address:any

                Confirm adding it?(y/n): y
                Added.

        Optionally, clean the terminal history if it was not disabled. There are two options:

          #. Clean it all

              .. code-block:: console

                # history -c


          #. Clean any specific line

              .. code-block:: console

                # history -d <line to delete>


    #. To enable the communication with the Wazuh manager, edit the Wazuh agent's configuration file placed at ``/var/ossec/etc/ossec.conf``.

         .. include:: ../../_templates/registrations/common/client_server_section.rst


    #. Restart the Wazuh agent:

      .. include:: ../../_templates/common/linux/restart_agent.rst



  .. group-tab:: Windows host


    Open a Powershell session in the Wazuh agent's host as an ``Administrator``.

    .. include:: ../../_templates/windows/installation_directory.rst


    #. Add the Wazuh agent to the Wazuh manager.

         If the Wazuh API is running over HTTPS and it is using a self-signed certificate, the function below has to be executed in Powershell. Values in angle brackets have to be replaced:

         .. code-block:: powershell

           function Ignore-SelfSignedCerts {
               add-type @"
                   using System.Net;
                   using System.Security.Cryptography.X509Certificates;

                   public class PolicyCert : ICertificatePolicy {
                       public PolicyCert() {}
                       public bool CheckValidationResult(
                           ServicePoint sPoint, X509Certificate cert,
                           WebRequest wRequest, int certProb) {
                           return true;
                       }
                   }
           "@
               [System.Net.ServicePointManager]::CertificatePolicy = new-object PolicyCert
           }

           $protocol = "https"
           $host_name = "<MANAGER_IP>"
           $port = "55000"
           $username = "<API_USERNAME>"
           $password = "<API_PASSWORD>"
           $endpoint = "/agents"
           $body_json = @{name = "<AGENT_NAME>"} | ConvertTo-Json

           $base_url = $protocol + "://" + $host_name + ":" + $port
           $endpoint_url = $base_url + $endpoint
           $login_url = $base_url + "/security/user/authenticate"
           $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username, $password)))
           $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
           $headers.Add("Content-Type", 'application/json')
           $headers.Add("Authorization", "Basic " + $base64AuthInfo)

           Ignore-SelfSignedCerts
           $token_response = Invoke-RestMethod -Uri $login_url -Headers $headers
           $headers["Authorization"] = "Bearer " + $token_response.data.token

           $agent_ref = Invoke-RestMethod -Method POST -Uri $endpoint_url -Body $body_json -Headers $headers
           echo $agent_ref | ConvertTo-Json

         The commands above return the Wazuh agent's ID and registration key.

         .. code-block:: none
          :class: output

            {
              "data": {
                        "id": "001",
                        "key": "MDAxIE5ld0FnZW50IDEwLjAuMC44IDM0MGQ1NjNkODQyNjcxMWIyYzUzZTE1MGIzYjEyYWVlMTU1ODgxMzVhNDE3MWQ1Y2IzZDY4M2Y0YjA0ZWVjYzM="
                      },
              "error": 0
            }


    #. Import the registration key to the Wazuh agent using ``manage_agents`` utility:

         .. code-block:: console

          # & "C:\Program Files (x86)\ossec-agent\manage_agents.exe" -i <key>

         An example output of the command looks as follows:

         .. code-block:: none
                :class: output

                Agent information:
                   ID:001
                   Name:agent_1
                   IP Address:any

                Confirm adding it?(y/n): y
                Added.

        Optionally, clean the terminal history if it was not disabled. There are two options:

          #. Clean it all

              .. code-block:: console

                # Clear-History


          #. Clean any specific line

              .. code-block:: console

                # Clear-History -Id <line IDs separated by a comma and a whitespace>


    #. To enable the communication with the Wazuh manager, edit the Wazuh agent's configuration file placed at ``C:\Program Files (x86)\ossec-agent\ossec.conf``.

         .. include:: ../../_templates/registrations/common/client_server_section.rst


    #. Restart the Wazuh agent:

      .. include:: ../../_templates/common/windows/restart_agent.rst



  .. group-tab:: MacOS X host


    #. Open a terminal in the Wazuh agent's host as a ``root`` user. To add the Wazuh agent to the Wazuh manager and extract the registration key execute the following Wazuh API request :api-ref:`POST /agents <operation/api.controllers.agent_controller.add_agent>` and replacing the values in the angle brackets:

         .. code-block:: console

          # curl -k -X POST -d '{"name":"<agent_name>","ip":"<agent_IP>"}' "https://localhost:55000/agents?pretty=true" -H "Content-Type:application/json" -H "Authorization: Bearer $TOKEN"

         The output of the Wazuh API request returns the registration key:

         .. code-block:: none
                :class: output

                {
                    "error": 0,
                    "data": {
                        "id": "001",
                        "key": "MDAxIE5ld0FnZW50IDEwLjAuMC44IDM0MGQ1NjNkODQyNjcxMWIyYzUzZTE1MGIzYjEyYWVlMTU1ODgxMzVhNDE3MWQ1Y2IzZDY4M2Y0YjA0ZWVjYzM=",
                    },
                }

         More information about API credentials and HTTPS support can be found on :ref:`Wazuh API configuration<api_configuration>`.


    #. Import the registration key to the Wazuh agent using ``manage_agents`` utility. Replace the Wazuh agent's registration key:

         .. code-block:: console

           # /Library/Ossec/bin/manage_agents -i <key>

         An example output of the command looks as follows:

         .. code-block:: none
                :class: output

                Agent information:
                    ID:001
                    Name:agent_1
                    IP Address:any

                Confirm adding it?(y/n): y
                Added.

        Optionally, clean the terminal history if it was not disabled. There are two options:

          #. Clean it all

              .. code-block:: console

                # history -c


          #. Clean any specific line

              .. code-block:: console

                # history -d <line to delete>


    #. To enable the communication with the Wazuh manager, edit the Wazuh agent's configuration file placed at ``/Library/Ossec/etc/ossec.conf``.

         .. include:: ../../_templates/registrations/common/client_server_section.rst


    #. Restart the Wazuh agent:

      .. include:: ../../_templates/common/macosx/restart_agent.rst
