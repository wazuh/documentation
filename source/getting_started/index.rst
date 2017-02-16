.. _getting_started:

Getting started
===============

Wazuh is an open source project for security visibility, compliance and infrastructure monitoring. It was born as a fork of OSSEC HIDS and was then integrated with Elastic Stack and OpenSCAP, evolving into a more comprehensive solution. Below is a brief description of these tools and what they do:

.. thumbnail:: ../images/ossec_openscap_elastic_1024x445.png
   :title: OSSEC, OpenSCAP and Elastic Stack
   :align: center
   :width: 100%

- `OSSEC HIDS <http://ossec.github.io>`_ is a **H**\ ost based **I**\ ntrusion **D**\ etection **S**\ ystem used both for security visibility and for compliance monitoring. Its architecture is based on a multi-platform agent that forwards system data (e.g log messages, file hashes, detected anomalies) to a central manager, where it is further analyzed and processed, resulting in security alerts.  Agents convey event data to the central manager via a secure and authenticated channel.  Additionally, OSSEC HIDS functions as a centralized syslog server and agentless configuration monitoring system, providing security insight into the events and changes on agentless devices such as firewalls, switches, routers, access points, network appliances, etc.

+ `OpenSCAP <https://www.open-scap.org>`_ is an `OVAL <https://oval.mitre.org/>`_ (Open Vulnerability Assessment Language) and `XCCDF <https://scap.nist.gov/specifications/xccdf/>`_ (Extensible Configuration Checklist Description Format) interpreter used to check system configurations and to detect vulnerable applications.  It is a well recognized tool for checking the compliance and hardening of systems against industry standard security baselines for enterprise environments. 

- `Elastic Stack <https://www.elastic.co>`_ is a suite of tools (Filebeat, Logstash, Elasticsearch, Kibana) used to collect, parse, index, store, search, and present log data. It provides a web frontend useful for gaining a high level dashboard views of events, as well as for performing advanced analytics and data mining deep into your store of event data.


.. topic:: Table of Contents

   This document will help you understand Wazuh components, functionality and architecture.

.. toctree::
   :maxdepth: 2

   components
   architecture
   use_cases
