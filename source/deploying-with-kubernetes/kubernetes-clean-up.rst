.. Copyright (C) 2020 Wazuh, Inc.

.. _kubernetes_clean_up:


Clean Up
========

Steps to perform a clean up of all deployments, services and volumes.

Wazuh cluster
-------------

The deployment of the Wazuh cluster of managers involves the use of different `StatefulSet <https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/>`_ elements as well as configuration maps and services.

1. First, remove the services related to the Wazuh cluster.

    List the services created:

    .. code-block:: console

        $ kubectl get services --namespace wazuh

    .. code-block:: none
        :class: output

        NAME                  TYPE           CLUSTER-IP       EXTERNAL-IP        PORT(S)                          AGE
        elasticsearch         ClusterIP      172.20.247.17    <none>             9200/TCP                         6d
        kibana                ClusterIP      172.20.121.19    <none>             5601/TCP                         6d
        logstash              ClusterIP      172.20.160.68    <none>             5000/TCP                         6d
        wazuh                 LoadBalancer   172.20.240.162   internal-ae32...   1515:30732/TCP,55000:30839/TCP   6d
        wazuh-cluster         ClusterIP      None             <none>             1516/TCP                         6d
        wazuh-elasticsearch   ClusterIP      None             <none>             9300/TCP                         6d
        wazuh-nginx           LoadBalancer   172.20.166.239   internal-ac0c...   80:30409/TCP,443:32575/TCP       6d
        wazuh-workers         LoadBalancer   172.20.17.252    internal-aec3...   1514:32047/TCP                   6d

    Delete the corresponding services:

    .. code-block:: console

        $ kubectl delete service wazuh-cluster --namespace wazuh
        $ kubectl delete service wazuh-workers --namespace wazuh
        $ kubectl delete service wazuh --namespace wazuh

2. Remove the *StatefulSet* elements.

    .. code-block:: console

        $ kubectl get StatefulSet --namespace wazuh

    .. code-block:: none
        :class: output

        NAME                     DESIRED   CURRENT   AGE
        wazuh-elasticsearch      1         1         6d
        wazuh-manager-master     1         1         6d
        wazuh-manager-worker-0   1         1         6d
        wazuh-manager-worker-1   1         1         6d

    Remove all the *StatefulSet* elements of the Wazuh cluster:

    .. code-block:: console

        $ kubectl delete StatefulSet wazuh-manager-master --namespace wazuh
        $ kubectl delete StatefulSet wazuh-manager-worker-0 --namespace wazuh
        $ kubectl delete StatefulSet wazuh-manager-worker-1 --namespace wazuh

3. Remove the configuration maps.

    .. code-block:: console

        $ kubectl get ConfigMap --namespace wazuh

    .. code-block:: none
        :class: output

        NAME                          DATA      AGE
        wazuh-manager-master-conf     1         6d
        wazuh-manager-worker-0-conf   1         6d
        wazuh-manager-worker-1-conf   1         6d

    .. code-block:: console

        $ kubectl delete ConfigMap wazuh-manager-master-conf --namespace wazuh
        $ kubectl delete ConfigMap wazuh-manager-worker-0-conf --namespace wazuh
        $ kubectl delete ConfigMap wazuh-manager-worker-1-conf --namespace wazuh


4. Remove the persistent volume claims.

    .. code-block:: console

        $ kubectl get persistentvolumeclaim --namespace wazuh

    .. code-block:: none
        :class: output

        NAME                                            STATUS    VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS             AGE
        wazuh-elasticsearch-wazuh-elasticsearch-0       Bound     pvc-b3226ad3-f7c4-11e8-b9b8-022ada63b4ac   30Gi       RWO            gp2-encrypted-retained   6d
        wazuh-manager-master-wazuh-manager-master-0     Bound     pvc-fb821971-f7c4-11e8-b9b8-022ada63b4ac   10Gi       RWO            gp2-encrypted-retained   6d
        wazuh-manager-worker-wazuh-manager-worker-0-0   Bound     pvc-ffe7bf66-f7c4-11e8-b9b8-022ada63b4ac   10Gi       RWO            gp2-encrypted-retained   6d
        wazuh-manager-worker-wazuh-manager-worker-1-0   Bound     pvc-024466da-f7c5-11e8-b9b8-022ada63b4ac   10Gi       RWO            gp2-encrypted-retained   6d

    .. code-block:: console

        $ kubectl delete persistentvolumeclaim wazuh-manager-master-wazuh-manager-master-0 --namespace wazuh
        $ kubectl delete persistentvolumeclaim wazuh-manager-master-wazuh-manager-worker-0-0 --namespace wazuh
        $ kubectl delete persistentvolumeclaim wazuh-manager-master-wazuh-manager-worker-1-0 --namespace wazuh

5. Last step, remove the persistent volumes.

    .. code-block:: console

        $ kubectl get persistentvolume

    .. code-block:: none
        :class: output

        NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS        CLAIM                                                         STORAGECLASS             REASON    AGE
        pvc-024466da-f7c5-11e8-b9b8-022ada63b4ac   10Gi       RWO            Retain           Bound         wazuh/wazuh-manager-worker-wazuh-manager-worker-1-0           gp2-encrypted-retained             6d
        pvc-b3226ad3-f7c4-11e8-b9b8-022ada63b4ac   30Gi       RWO            Retain           Bound         wazuh/wazuh-elasticsearch-wazuh-elasticsearch-0               gp2-encrypted-retained             6d
        pvc-fb821971-f7c4-11e8-b9b8-022ada63b4ac   10Gi       RWO            Retain           Bound         wazuh/wazuh-manager-master-wazuh-manager-master-0             gp2-encrypted-retained             6d
        pvc-ffe7bf66-f7c4-11e8-b9b8-022ada63b4ac   10Gi       RWO            Retain           Bound         wazuh/wazuh-manager-worker-wazuh-manager-worker-0-0           gp2-encrypted-retained             6d

    .. code-block:: console

        $ kubectl delete persistentvolume pvc-fb821971-f7c4-11e8-b9b8-022ada63b4ac
        $ kubectl delete persistentvolume pvc-ffe7bf66-f7c4-11e8-b9b8-022ada63b4ac
        $ kubectl delete persistentvolume pvc-024466da-f7c5-11e8-b9b8-022ada63b4ac

Elasticsearch
-------------

1. The first step is to remove the services related to Elasticsearch.

    .. code-block:: console

        $ kubectl get services --namespace wazuh

    .. code-block:: none
        :class: output

        NAME                  TYPE           CLUSTER-IP       EXTERNAL-IP        PORT(S)                          AGE
        elasticsearch         ClusterIP      172.20.247.17    <none>             9200/TCP                         6d
        kibana                ClusterIP      172.20.121.19    <none>             5601/TCP                         6d
        logstash              ClusterIP      172.20.160.68    <none>             5000/TCP                         6d
        wazuh-elasticsearch   ClusterIP      None             <none>             9300/TCP                         6d
        wazuh-nginx           LoadBalancer   172.20.166.239   internal-ac0c...   80:30409/TCP,443:32575/TCP       6d

    .. code-block:: console

        $ kubectl delete service elasticsearch --namespace wazuh
        $ kubectl delete service wazuh-elasticsearch --namespace wazuh

2. Remove the *StatefulSet* elements.

    .. code-block:: console

        $ kubectl get StatefulSet --namespace wazuh

    .. code-block:: none
        :class: output

        NAME                     DESIRED   CURRENT   AGE
        wazuh-elasticsearch      1         1         6d

    .. code-block:: console

        $ kubectl delete StatefulSet wazuh-elasticsearch --namespace wazuh

3. Remove the persistent volume claims.

    .. code-block:: console

        $ kubectl get persistentvolumeclaim --namespace wazuh

    .. code-block:: none
        :class: output

        NAME                                            STATUS    VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS             AGE
        wazuh-elasticsearch-wazuh-elasticsearch-0       Bound     pvc-b3226ad3-f7c4-11e8-b9b8-022ada63b4ac   30Gi       RWO            gp2-encrypted-retained   6d

    .. code-block:: console

        $ kubectl delete persistentvolumeclaim wazuh-elasticsearch-wazuh-elasticsearch-0 --namespace wazuh

4. Remove the persistent volumes.

    .. code-block:: console

        $ kubectl get persistentvolume

    .. code-block:: none
        :class: output

        NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS        CLAIM                                                         STORAGECLASS             REASON    AGE
        pvc-024466da-f7c5-11e8-b9b8-022ada63b4ac   10Gi       RWO            Retain           Released      wazuh/wazuh-manager-worker-wazuh-manager-worker-1-0           gp2-encrypted-retained             6d
        pvc-b3226ad3-f7c4-11e8-b9b8-022ada63b4ac   30Gi       RWO            Retain           Bound         wazuh/wazuh-elasticsearch-wazuh-elasticsearch-0               gp2-encrypted-retained             6d
        pvc-fb821971-f7c4-11e8-b9b8-022ada63b4ac   10Gi       RWO            Retain           Released      wazuh/wazuh-manager-master-wazuh-manager-master-0             gp2-encrypted-retained             6d
        pvc-ffe7bf66-f7c4-11e8-b9b8-022ada63b4ac   10Gi       RWO            Retain           Released      wazuh/wazuh-manager-worker-wazuh-manager-worker-0-0           gp2-encrypted-retained             6d

    .. code-block:: console

        $ kubectl delete persistentvolume pvc-b3226ad3-f7c4-11e8-b9b8-022ada63b4ac

Logstash
--------

1. The first step is to remove the services related to Logstash.

    .. code-block:: console

        $ kubectl get services --namespace wazuh

    .. code-block:: none
        :class: output

        NAME                  TYPE           CLUSTER-IP       EXTERNAL-IP        PORT(S)                          AGE
        kibana                ClusterIP      172.20.121.19    <none>             5601/TCP                         6d
        logstash              ClusterIP      172.20.160.68    <none>             5000/TCP                         6d
        wazuh-nginx           LoadBalancer   172.20.166.239   internal-ac0c...   80:30409/TCP,443:32575/TCP       6d

    .. code-block:: console

        $ kubectl delete service logstash --namespace wazuh

2. Remove the deployment.

    .. code-block:: console

        $ kubectl get deploy --namespace wazuh

    .. code-block:: none
        :class: output

        NAME             DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
        wazuh-kibana     1         1         1            1           6d
        wazuh-logstash   1         1         1            1           6d
        wazuh-nginx      1         1         1            1           6d

    .. code-block:: console

        $ kubectl delete deploy wazuh-logstash --namespace wazuh

Kibana and Nginx
----------------

1. First, remove the services related to Kibana and Nginx.

    .. code-block:: console

        $ kubectl get services --namespace wazuh

    .. code-block:: none
        :class: output

        NAME                  TYPE           CLUSTER-IP       EXTERNAL-IP        PORT(S)                          AGE
        kibana                ClusterIP      172.20.121.19    <none>             5601/TCP                         6d
        wazuh-nginx           LoadBalancer   172.20.166.239   internal-ac0c...   80:30409/TCP,443:32575/TCP       6d

    .. code-block:: console

        $ kubectl delete service kibana --namespace wazuh
        $ kubectl delete service wazuh-nginx --namespace wazuh

2. Remove the deployments.

    .. code-block:: console

        $ kubectl get deploy --namespace wazuh

    .. code-block:: none
        :class: output

        NAME             DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
        wazuh-kibana     1         1         1            1           6d
        wazuh-nginx      1         1         1            1           6d

    .. code-block:: console

        $ kubectl delete deploy wazuh-kibana --namespace wazuh
        $ kubectl delete deploy wazuh-nginx --namespace wazuh

.. warning::
    Do not forget to delete the volumes manually in AWS.
