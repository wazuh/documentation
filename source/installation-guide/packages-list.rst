.. Copyright (C) 2015–2022 Wazuh, Inc.

.. meta::
  :description: Find the packages required for Wazuh installation on this page. Available for AIX, Linux, HP-UX, macOS, Solaris, and Windows.

Packages list
=============

This download page contains packages required for the Wazuh installation:

- `Wazuh manager and Wazuh agent`_

   - `Linux`_
   - `Windows`_
   - `macOS`_
   - `Solaris`_
   - `AIX`_
   - `HP-UX`_

- `Wazuh indexer`_
- `Wazuh dashboard`_
- `Wazuh Kibana plugin`_
- `Wazuh Splunk app`_
- `Filebeat`_
- `Virtual machine`_
- `Amazon Machine Image`_
- `MSU`_

.. _Wazuh_manager_agent_packages_list:

Wazuh manager and Wazuh agent
-----------------------------

Linux
^^^^^

.. |Amazon_i386_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm.sha512>`__)

.. |Amazon_x86_64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm.sha512>`__)

.. |Amazon_x86_64_manager| replace:: `wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm <|RPM_MANAGER_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm.sha512>`__)

.. |Amazon_aarch64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm.sha512>`__)

.. |Amazon_aarch64_manager| replace:: `wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm <|RPM_MANAGER_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm.sha512>`__)

.. |Amazon_armhf_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm.sha512>`__)

.. |CentOS7_powerpc_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_PPC|.ppc64le.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_PPC|.ppc64le.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_PPC|.ppc64le.rpm.sha512>`__)

.. |CentOS6_i386_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm.sha512>`__)

.. |CentOS6_x86_64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm.sha512>`__)

.. |CentOS6_x86_64_manager| replace:: `wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm <|RPM_MANAGER_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm.sha512>`__)

.. |CentOS6_aarch64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm.sha512>`__)

.. |CentOS6_aarch64_manager| replace:: `wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm <|RPM_MANAGER_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm.sha512>`__)

.. |CentOS6_armhf_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm.sha512>`__)

.. |CentOS5_i386_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386_EL5|.el5.i386.rpm <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/yum5/i386/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386_EL5|.el5.i386.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386_EL5|.el5.i386.rpm.sha512>`__)

.. |CentOS5_x86_64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86_EL5|.el5.x86_64.rpm <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/yum5/x86_64/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86_EL5|.el5.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86_EL5|.el5.x86_64.rpm.sha512>`__)

.. |Debian9_powerpc_agent| replace:: `wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_PPC|_ppc64el.deb <|DEB_AGENT_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_PPC|_ppc64el.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_PPC|_ppc64el.deb.sha512>`__)

.. |Debian7_i386_agent| replace:: `wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_I386|_i386.deb <|DEB_AGENT_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_I386|_i386.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_I386|_i386.deb.sha512>`__)

.. |Debian7_x86_64_agent| replace:: `wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_X86|_amd64.deb <|DEB_AGENT_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_X86|_amd64.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_X86|_amd64.deb.sha512>`__)

.. |Debian7_x86_64_manager| replace:: `wazuh-manager_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_X86|_amd64.deb <|DEB_MANAGER_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_X86|_amd64.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_X86|_amd64.deb.sha512>`__)

.. |Debian7_aarch64_agent| replace:: `wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_AARCH64|_arm64.deb <|DEB_AGENT_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_AARCH64|_arm64.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_AARCH64|_arm64.deb.sha512>`__)

.. |Debian7_aarch64_manager| replace:: `wazuh-manager_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_AARCH64|_arm64.deb <|DEB_MANAGER_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_AARCH64|_arm64.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_AARCH64|_arm64.deb.sha512>`__)

.. |Debian7_armhf_agent| replace:: `wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_ARMHF|_armhf.deb <|DEB_AGENT_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_ARMHF|_armhf.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_ARMHF|_armhf.deb.sha512>`__)

.. |Fedora22_i386_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm.sha512>`__)

.. |Fedora22_x86_64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm.sha512>`__)

.. |Fedora22_x86_64_manager| replace:: `wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm <|RPM_MANAGER_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm.sha512>`__)

.. |Fedora22_aarch64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm.sha512>`__)

.. |Fedora22_aarch64_manager| replace:: `wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm <|RPM_MANAGER_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm.sha512>`__)

.. |Fedora22_armhf_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm.sha512>`__)

.. |OpenSUSE_i386_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm.sha512>`__)

.. |OpenSUSE_x86_64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm.sha512>`__)

.. |OpenSUSE_x86_64_manager| replace:: `wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm <|RPM_MANAGER_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm.sha512>`__)

.. |OpenSUSE_aarch64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm.sha512>`__)

.. |OpenSUSE_aarch64_manager| replace:: `wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm <|RPM_MANAGER_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm.sha512>`__)

.. |OpenSUSE_armhf_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm.sha512>`__)

.. |Oracle6_i386_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm.sha512>`__)

.. |Oracle6_x86_64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm.sha512>`__)

.. |Oracle6_x86_64_manager| replace:: `wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm <|RPM_MANAGER_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm.sha512>`__)

.. |Oracle6_aarch64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm.sha512>`__)

.. |Oracle6_aarch64_manager| replace:: `wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm <|RPM_MANAGER_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm.sha512>`__)

.. |Oracle6_armhf_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm.sha512>`__)

.. |Oracle5_i386_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386_EL5|.el5.i386.rpm <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/yum5/i386/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386_EL5|.el5.i386.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386_EL5|.el5.i386.rpm.sha512>`__)

.. |Oracle5_x86_64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86_EL5|.el5.x86_64.rpm <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/yum5/x86_64/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86_EL5|.el5.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86_EL5|.el5.x86_64.rpm.sha512>`__)

.. |RHEL6_i386_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm.sha512>`__)

.. |RHEL6_x86_64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm.sha512>`__)

.. |RHEL6_x86_64_manager| replace:: `wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm <|RPM_MANAGER_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm.sha512>`__)

.. |RHEL6_aarch64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm.sha512>`__)

.. |RHEL6_aarch64_manager| replace:: `wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm <|RPM_MANAGER_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm.sha512>`__)

.. |RHEL6_armhf_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm.sha512>`__)

.. |RHEL5_i386_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386_EL5|.el5.i386.rpm <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/yum5/i386/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386_EL5|.el5.i386.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386_EL5|.el5.i386.rpm.sha512>`__)

.. |RHEL5_x86_64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86_EL5|.el5.x86_64.rpm <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/yum5/x86_64/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86_EL5|.el5.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86_EL5|.el5.x86_64.rpm.sha512>`__)

.. |SUSE12_i386_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386|.i386.rpm.sha512>`__)

.. |SUSE12_x86_64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86|.x86_64.rpm.sha512>`__)

.. |SUSE12_x86_64_manager| replace:: `wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm <|RPM_MANAGER_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_X86|.x86_64.rpm.sha512>`__)

.. |SUSE12_aarch64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_AARCH64|.aarch64.rpm.sha512>`__)

.. |SUSE12_aarch64_manager| replace:: `wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm <|RPM_MANAGER_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_MANAGER_AARCH64|.aarch64.rpm.sha512>`__)

.. |SUSE12_armhf_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm <|RPM_AGENT_URL|-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_ARMHF|.armv7hl.rpm.sha512>`__)

.. |SUSE11_i386_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386_EL5|.el5.i386.rpm <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/yum5/i386/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386_EL5|.el5.i386.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_I386_EL5|.el5.i386.rpm.sha512>`__)

.. |SUSE11_x86_64_agent| replace:: `wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86_EL5|.el5.x86_64.rpm <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/yum5/x86_64/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86_EL5|.el5.x86_64.rpm>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent-|WAZUH_CURRENT|-|WAZUH_REVISION_YUM_AGENT_X86_EL5|.el5.x86_64.rpm.sha512>`__)

.. |Ubuntu12_i386_agent| replace:: `wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_I386|_i386.deb <|DEB_AGENT_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_I386|_i386.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_I386|_i386.deb.sha512>`__)

.. |Ubuntu12_x86_64_agent| replace:: `wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_X86|_amd64.deb <|DEB_AGENT_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_X86|_amd64.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_X86|_amd64.deb.sha512>`__)

.. |Ubuntu12_x86_64_manager| replace:: `wazuh-manager_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_X86|_amd64.deb <|DEB_MANAGER_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_X86|_amd64.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_X86|_amd64.deb.sha512>`__)

.. |Ubuntu12_aarch64_agent| replace:: `wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_AARCH64|_arm64.deb <|DEB_AGENT_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_AARCH64|_arm64.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_AARCH64|_arm64.deb.sha512>`__)

.. |Ubuntu12_aarch64_manager| replace:: `wazuh-manager_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_AARCH64|_arm64.deb <|DEB_MANAGER_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_AARCH64|_arm64.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_AARCH64|_arm64.deb.sha512>`__)

.. |Ubuntu12_armhf_agent| replace:: `wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_ARMHF|_armhf.deb <|DEB_AGENT_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_ARMHF|_armhf.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_ARMHF|_armhf.deb.sha512>`__)

.. |Raspbian_x86_64_agent| replace:: `wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_X86|_amd64.deb <|DEB_AGENT_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_X86|_amd64.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_X86|_amd64.deb.sha512>`__)

.. |Raspbian_x86_64_manager| replace:: `wazuh-manager_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_X86|_amd64.deb <|DEB_MANAGER_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_X86|_amd64.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_X86|_amd64.deb.sha512>`__)

.. |Raspbian_aarch64_agent| replace:: `wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_AARCH64|_arm64.deb <|DEB_AGENT_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_AARCH64|_arm64.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_AARCH64|_arm64.deb.sha512>`__)

.. |Raspbian_aarch64_manager| replace:: `wazuh-manager_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_AARCH64|_arm64.deb <|DEB_MANAGER_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_AARCH64|_arm64.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-manager_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_MANAGER_AARCH64|_arm64.deb.sha512>`__)

.. |Raspbian_armhf_agent| replace:: `wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_ARMHF|_armhf.deb <|DEB_AGENT_URL|_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_ARMHF|_armhf.deb>`__ (`sha512 <|CHECKSUMS_URL||WAZUH_CURRENT|/wazuh-agent_|WAZUH_CURRENT|-|WAZUH_REVISION_DEB_AGENT_ARMHF|_armhf.deb.sha512>`__)

+-----------------------+-------------------+--------------+------------------------------------------+
| Distribution          | Version           | Architecture | Package                                  |
+=======================+===================+==============+==========================================+
|                       |                   |    i386      | |Amazon_i386_agent|                      |
+ Amazon Linux          +  1 and 2          +--------------+------------------------------------------+
|                       |                   |              | |Amazon_x86_64_agent|                    |
+                       +                   +    x86_64    +------------------------------------------+
|                       |                   |              | |Amazon_x86_64_manager|                  |
+                       +                   +--------------+------------------------------------------+
|                       |                   |              | |Amazon_aarch64_agent|                   |
+                       +                   +    aarch64   +------------------------------------------+
|                       |                   |              | |Amazon_aarch64_manager|                 |
+                       +                   +--------------+------------------------------------------+
|                       |                   |    armhf     | |Amazon_armhf_agent|                     |
+-----------------------+-------------------+--------------+------------------------------------------+
|                       |  7 or later       |    powerpc   | |CentOS7_powerpc_agent|                  |
+ CentOS                +-------------------+--------------+------------------------------------------+
|                       |                   |    i386      | |CentOS6_i386_agent|                     |
+                       +  6 or later       +--------------+------------------------------------------+
|                       |                   |              | |CentOS6_x86_64_agent|                   |
+                       +                   +    x86_64    +------------------------------------------+
|                       |                   |              | |CentOS6_x86_64_manager|                 |
+                       +                   +--------------+------------------------------------------+
|                       |                   |              | |CentOS6_aarch64_agent|                  |
+                       +                   +    aarch64   +------------------------------------------+
|                       |                   |              | |CentOS6_aarch64_manager|                |
+                       +                   +--------------+------------------------------------------+
|                       |                   |    armhf     | |CentOS6_armhf_agent|                    |
+                       +-------------------+--------------+------------------------------------------+
|                       |                   |    i386      | |CentOS5_i386_agent|                     |
+                       +  5                +--------------+------------------------------------------+
|                       |                   |    x86_64    | |CentOS5_x86_64_agent|                   |
+-----------------------+-------------------+--------------+------------------------------------------+
|                       |  9 or later       |    powerpc   | |Debian9_powerpc_agent|                  |
+ Debian                +-------------------+--------------+------------------------------------------+
|                       |                   |    i386      | |Debian7_i386_agent|                     |
+                       +  7 or later       +--------------+------------------------------------------+
|                       |                   |              | |Debian7_x86_64_agent|                   |
+                       +                   +    x86_64    +------------------------------------------+
|                       |                   |              | |Debian7_x86_64_manager|                 |
+                       +                   +--------------+------------------------------------------+
|                       |                   |              | |Debian7_aarch64_agent|                  |
+                       +                   +    aarch64   +------------------------------------------+
|                       |                   |              | |Debian7_aarch64_manager|                |
+                       +                   +--------------+------------------------------------------+
|                       |                   |    armhf     | |Debian7_armhf_agent|                    |
+-----------------------+-------------------+--------------+------------------------------------------+
|                       |                   |    i386      | |Fedora22_i386_agent|                    |
+ Fedora                +  22 or later      +--------------+------------------------------------------+
|                       |                   |              | |Fedora22_x86_64_agent|                  |
+                       +                   +    x86_64    +------------------------------------------+
|                       |                   |              | |Fedora22_x86_64_manager|                |
+                       +                   +--------------+------------------------------------------+
|                       |                   |              | |Fedora22_aarch64_agent|                 |
+                       +                   +    aarch64   +------------------------------------------+
|                       |                   |              | |Fedora22_aarch64_manager|               |
+                       +                   +--------------+------------------------------------------+
|                       |                   |    armhf     | |Fedora22_armhf_agent|                   |
+-----------------------+-------------------+--------------+------------------------------------------+
|                       |                   |    i386      | |OpenSUSE_i386_agent|                    |
+ OpenSUSE              +  42 or later      +--------------+------------------------------------------+
|                       |                   |              | |OpenSUSE_x86_64_agent|                  |
+                       +                   +    x86_64    +------------------------------------------+
|                       |                   |              | |OpenSUSE_x86_64_manager|                |
+                       +                   +--------------+------------------------------------------+
|                       |                   |              | |OpenSUSE_aarch64_agent|                 |
+                       +                   +    aarch64   +------------------------------------------+
|                       |                   |              | |OpenSUSE_aarch64_manager|               |
+                       +                   +--------------+------------------------------------------+
|                       |                   |    armhf     | |OpenSUSE_armhf_agent|                   |
+-----------------------+-------------------+--------------+------------------------------------------+
|                       |                   |    i386      | |Oracle6_i386_agent|                     |
+ Oracle Linux          +  6 or later       +--------------+------------------------------------------+
|                       |                   |              | |Oracle6_x86_64_agent|                   |
+                       +                   +    x86_64    +------------------------------------------+
|                       |                   |              | |Oracle6_x86_64_manager|                 |
+                       +                   +--------------+------------------------------------------+
|                       |                   |              | |Oracle6_aarch64_agent|                  |
+                       +                   +    aarch64   +------------------------------------------+
|                       |                   |              | |Oracle6_aarch64_manager|                |
+                       +                   +--------------+------------------------------------------+
|                       |                   |    armhf     | |Oracle6_armhf_agent|                    |
+                       +-------------------+--------------+------------------------------------------+
|                       |                   |    i386      | |Oracle5_i386_agent|                     |
+                       +  5                +--------------+------------------------------------------+
|                       |                   |    x86_64    | |Oracle5_x86_64_agent|                   |
+-----------------------+-------------------+--------------+------------------------------------------+
|                       |                   |    i386      | |RHEL6_i386_agent|                       |
+ Red Hat               +  6 or later       +--------------+------------------------------------------+
| Enterprise Linux      |                   |              | |RHEL6_x86_64_agent|                     |
+                       +                   +    x86_64    +------------------------------------------+
|                       |                   |              | |RHEL6_x86_64_manager|                   |
+                       +                   +--------------+------------------------------------------+
|                       |                   |              | |RHEL6_aarch64_agent|                    |
+                       +                   +    aarch64   +------------------------------------------+
|                       |                   |              | |RHEL6_aarch64_manager|                  |
+                       +                   +--------------+------------------------------------------+
|                       |                   |    armhf     | |RHEL6_armhf_agent|                      |
+                       +-------------------+--------------+------------------------------------------+
|                       |                   |    i386      | |RHEL5_i386_agent|                       |
+                       +  5                +--------------+------------------------------------------+
|                       |                   |    x86_64    | |RHEL5_x86_64_agent|                     |
+-----------------------+-------------------+--------------+------------------------------------------+
|                       |                   |    i386      | |SUSE12_i386_agent|                      |
+ SUSE                  +  12               +--------------+------------------------------------------+
|                       |                   |              | |SUSE12_x86_64_agent|                    |
+                       +                   +    x86_64    +------------------------------------------+
|                       |                   |              | |SUSE12_x86_64_manager|                  |
+                       +                   +--------------+------------------------------------------+
|                       |                   |              | |SUSE12_aarch64_agent|                   |
+                       +                   +    aarch64   +------------------------------------------+
|                       |                   |              | |SUSE12_aarch64_manager|                 |
+                       +                   +--------------+------------------------------------------+
|                       |                   |    armhf     | |SUSE12_armhf_agent|                     |
+                       +-------------------+--------------+------------------------------------------+
|                       |                   |    i386      | |SUSE11_i386_agent|                      |
+                       +  11               +--------------+------------------------------------------+
|                       |                   |    x86_64    | |SUSE11_x86_64_agent|                    |
+-----------------------+-------------------+--------------+------------------------------------------+
|                       |                   |    i386      | |Ubuntu12_i386_agent|                    |
+ Ubuntu                +  12 or later      +--------------+------------------------------------------+
|                       |                   |              | |Ubuntu12_x86_64_agent|                  |
+                       +                   +    x86_64    +------------------------------------------+
|                       |                   |              | |Ubuntu12_x86_64_manager|                |
+                       +                   +--------------+------------------------------------------+
|                       |                   |              | |Ubuntu12_aarch64_agent|                 |
+                       +                   +    aarch64   +------------------------------------------+
|                       |                   |              | |Ubuntu12_aarch64_manager|               |
+                       +                   +--------------+------------------------------------------+
|                       |                   |    armhf     | |Ubuntu12_armhf_agent|                   |
+-----------------------+-------------------+--------------+------------------------------------------+
|                       |                   |              | |Raspbian_x86_64_agent|                  |
+                       +                   +    x86_64    +------------------------------------------+
|                       |                   |              | |Raspbian_x86_64_manager|                |
+ Raspbian OS           + Buster or greater +--------------+------------------------------------------+
|                       |                   |              | |Raspbian_aarch64_agent|                 |
+                       +                   +    aarch64   +------------------------------------------+
|                       |                   |              | |Raspbian_aarch64_manager|               |
+                       +                   +--------------+------------------------------------------+
|                       |                   |    armhf     | |Raspbian_armhf_agent|                   |
+-----------------------+-------------------+--------------+------------------------------------------+

Windows
^^^^^^^

.. |WindowsXP_32_64| replace:: `wazuh-agent-|WAZUH_CURRENT_WINDOWS|-|WAZUH_REVISION_WINDOWS|.msi <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_WINDOWS|/windows/wazuh-agent-|WAZUH_CURRENT_WINDOWS|-|WAZUH_REVISION_WINDOWS|.msi>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_WINDOWS|/checksums/wazuh/|WAZUH_CURRENT_WINDOWS|/wazuh-agent-|WAZUH_CURRENT_WINDOWS|-|WAZUH_REVISION_WINDOWS|.msi.sha512>`__)

+-----------------+--------------+---------------------------+
| Version         | Architecture | Package                   |
+=================+==============+===========================+
|  XP or later    |   32/64bits  | |WindowsXP_32_64|         |
+-----------------+--------------+---------------------------+

macOS
^^^^^

.. |macOS_64| replace:: `wazuh-agent-|WAZUH_CURRENT_OSX|-|WAZUH_REVISION_OSX|.pkg <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_OSX|/macos/wazuh-agent-|WAZUH_CURRENT_OSX|-|WAZUH_REVISION_OSX|.pkg>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_OSX|/checksums/wazuh/|WAZUH_CURRENT_OSX|/wazuh-agent-|WAZUH_CURRENT_OSX|-|WAZUH_REVISION_OSX|.pkg.sha512>`__)

+--------------+-------------------------+
| Architecture | Package                 |
+==============+=========================+
|    64bits    | |macOS_64|              |
+--------------+-------------------------+

Solaris
^^^^^^^

.. |Solaris10_i386| replace:: `wazuh-agent_v|WAZUH_CURRENT_SOLARIS10|-sol10-i386.pkg <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_SOLARIS10|/solaris/i386/10/wazuh-agent_v|WAZUH_CURRENT_SOLARIS10|-sol10-i386.pkg>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_SOLARIS10|/checksums/wazuh/|WAZUH_CURRENT_SOLARIS10|/wazuh-agent_v|WAZUH_CURRENT_SOLARIS10|-sol10-i386.pkg.sha512>`__)

.. |Solaris10_SPARC| replace:: `wazuh-agent_v|WAZUH_CURRENT_SOLARIS10|-sol10-sparc.pkg <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_SOLARIS10|/solaris/sparc/10/wazuh-agent_v|WAZUH_CURRENT_SOLARIS10|-sol10-sparc.pkg>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_SOLARIS10|/checksums/wazuh/|WAZUH_CURRENT_SOLARIS10|/wazuh-agent_v|WAZUH_CURRENT_SOLARIS10|-sol10-sparc.pkg.sha512>`__)

.. |Solaris11_i386| replace:: `wazuh-agent_v|WAZUH_CURRENT_SOLARIS11|-sol11-i386.p5p <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_SOLARIS11|/solaris/i386/11/wazuh-agent_v|WAZUH_CURRENT_SOLARIS11|-sol11-i386.p5p>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_SOLARIS11|/checksums/wazuh/|WAZUH_CURRENT_SOLARIS11|/wazuh-agent_v|WAZUH_CURRENT_SOLARIS11|-sol11-i386.p5p.sha512>`__)

.. |Solaris11_SPARC| replace:: `wazuh-agent_v|WAZUH_CURRENT_SOLARIS11|-sol11-sparc.p5p <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_SOLARIS11|/solaris/sparc/11/wazuh-agent_v|WAZUH_CURRENT_SOLARIS11|-sol11-sparc.p5p>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_SOLARIS11|/checksums/wazuh/|WAZUH_CURRENT_SOLARIS11|/wazuh-agent_v|WAZUH_CURRENT_SOLARIS11|-sol11-sparc.p5p.sha512>`__)

+---------+--------------+-------------------------+
| Version | Architecture | Package                 |
+=========+==============+=========================+
|         |     i386     | |Solaris10_i386|        |
+  10     +--------------+-------------------------+
|         |     SPARC    | |Solaris10_SPARC|       |
+---------+--------------+-------------------------+
|         |     i386     | |Solaris11_i386|        |
+  11     +--------------+-------------------------+
|         |     SPARC    | |Solaris11_SPARC|       |
+---------+--------------+-------------------------+

AIX
^^^

.. |AIX_powerpc| replace:: `wazuh-agent-|WAZUH_CURRENT_AIX|-|WAZUH_REVISION_AIX|.aix.ppc.rpm <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_AIX|/aix/wazuh-agent-|WAZUH_CURRENT_AIX|-|WAZUH_REVISION_AIX|.aix.ppc.rpm>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_AIX|/checksums/wazuh/|WAZUH_CURRENT_AIX|/wazuh-agent-|WAZUH_CURRENT_AIX|-|WAZUH_REVISION_AIX|.aix.ppc.rpm.sha512>`__)

+-----------------+--------------+----------------------------------------+
| Version         | Architecture | Package                                |
+=================+==============+========================================+
| 6.1 or greater  |    PowerPC   | |AIX_powerpc|                          |
+-----------------+--------------+----------------------------------------+

HP-UX
^^^^^

.. |HPUX_itanium| replace:: `wazuh-agent-|WAZUH_CURRENT_HPUX|-|WAZUH_REVISION_HPUX|-hpux-11v3-ia64.tar <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_HPUX|/hp-ux/wazuh-agent-|WAZUH_CURRENT_HPUX|-|WAZUH_REVISION_HPUX|-hpux-11v3-ia64.tar>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_HPUX|/checksums/wazuh/|WAZUH_CURRENT_HPUX|/wazuh-agent-|WAZUH_CURRENT_HPUX|-|WAZUH_REVISION_HPUX|-hpux-11v3-ia64.tar.sha512>`__)

+-----------------+--------------+-------------------+
| Version         | Architecture | Package           |
+=================+==============+===================+
|  11.31          |   Itanium    | |HPUX_itanium|    |
+-----------------+--------------+-------------------+


Wazuh indexer
-------------

.. |IndexerRPM| replace:: `wazuh-indexer-|WAZUH_CURRENT|-|WAZUH_INDEXER_CURRENT_REV|.|WAZUH_INDEXER_x64_RPM|.rpm <https://packages.wazuh.com/4.x/yum/wazuh-indexer-|WAZUH_CURRENT|-|WAZUH_INDEXER_CURRENT_REV|.|WAZUH_INDEXER_x64_RPM|.rpm>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_CURRENT|/wazuh-indexer-|WAZUH_CURRENT|-|WAZUH_INDEXER_CURRENT_REV|.|WAZUH_INDEXER_x64_RPM|.rpm.sha512>`__)

.. |IndexerDEB| replace:: `wazuh-indexer_|WAZUH_CURRENT|-|WAZUH_INDEXER_CURRENT_REV|_|WAZUH_INDEXER_x64_DEB|.deb <https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_|WAZUH_CURRENT|-|WAZUH_INDEXER_CURRENT_REV|_|WAZUH_INDEXER_x64_DEB|.deb>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_CURRENT|/wazuh-indexer_|WAZUH_CURRENT|-|WAZUH_INDEXER_CURRENT_REV|_|WAZUH_INDEXER_x64_DEB|.deb.sha512>`__)


+--------------+------------------+
| Package type | Package          |
+==============+==================+
|     RPM      | |IndexerRPM|     |
+--------------+------------------+
|     DEB      | |IndexerDEB|     |
+--------------+------------------+


Wazuh dashboard
---------------

.. |DashboardRPM| replace:: `wazuh-dashboard-|WAZUH_CURRENT|-|WAZUH_DASHBOARD_CURRENT_REV_RPM|.|WAZUH_DASHBOARD_x64_RPM|.rpm <https://packages.wazuh.com/4.x/yum/wazuh-dashboard-|WAZUH_CURRENT|-|WAZUH_DASHBOARD_CURRENT_REV_RPM|.|WAZUH_DASHBOARD_x64_RPM|.rpm>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_CURRENT|/wazuh-dashboard-|WAZUH_CURRENT|-|WAZUH_DASHBOARD_CURRENT_REV_RPM|.|WAZUH_DASHBOARD_x64_RPM|.rpm.sha512>`__)

.. |DashboardDEB| replace:: `wazuh-dashboard_|WAZUH_CURRENT|-|WAZUH_DASHBOARD_CURRENT_REV_DEB|_|WAZUH_DASHBOARD_x64_DEB|.deb <https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-dashboard/wazuh-dashboard_|WAZUH_CURRENT|-|WAZUH_DASHBOARD_CURRENT_REV_DEB|_|WAZUH_DASHBOARD_x64_DEB|.deb>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_CURRENT|/wazuh-dashboard_|WAZUH_CURRENT|-|WAZUH_DASHBOARD_CURRENT_REV_DEB|_|WAZUH_DASHBOARD_x64_DEB|.deb.sha512>`__)

+--------------+------------------+
| Package type | Package          |
+==============+==================+
|     RPM      | |DashboardRPM|   |
+--------------+------------------+
|     DEB      | |DashboardDEB|   |
+--------------+------------------+

Wazuh Kibana plugin
-------------------

For Wazuh |WAZUH_CURRENT|:

.. |WAZUH_KIBANA_7.10.2| replace:: `wazuh_kibana-|WAZUH_CURRENT|_7.10.2.zip <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/ui/kibana/wazuh_kibana-|WAZUH_CURRENT|_7.10.2-1.zip>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/checksums/wazuh/|WAZUH_CURRENT|/wazuh_kibana-|WAZUH_CURRENT|_7.10.2-1.zip.sha512>`__)

.. |WAZUH_KIBANA_7.16.0| replace:: `wazuh_kibana-|WAZUH_CURRENT|_7.16.0.zip <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/ui/kibana/wazuh_kibana-|WAZUH_CURRENT|_7.16.0-1.zip>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/checksums/wazuh/|WAZUH_CURRENT|/wazuh_kibana-|WAZUH_CURRENT|_7.16.0-1.zip.sha512>`__)

.. |WAZUH_KIBANA_7.16.1| replace:: `wazuh_kibana-|WAZUH_CURRENT|_7.16.1.zip <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/ui/kibana/wazuh_kibana-|WAZUH_CURRENT|_7.16.1-1.zip>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/checksums/wazuh/|WAZUH_CURRENT|/wazuh_kibana-|WAZUH_CURRENT|_7.16.1-1.zip.sha512>`__)

.. |WAZUH_KIBANA_7.16.2| replace:: `wazuh_kibana-|WAZUH_CURRENT|_7.16.2.zip <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/ui/kibana/wazuh_kibana-|WAZUH_CURRENT|_7.16.2-1.zip>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/checksums/wazuh/|WAZUH_CURRENT|/wazuh_kibana-|WAZUH_CURRENT|_7.16.2-1.zip.sha512>`__)

.. |WAZUH_KIBANA_7.16.3| replace:: `wazuh_kibana-|WAZUH_CURRENT|_7.16.3.zip <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/ui/kibana/wazuh_kibana-|WAZUH_CURRENT|_7.16.3-1.zip>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/checksums/wazuh/|WAZUH_CURRENT|/wazuh_kibana-|WAZUH_CURRENT|_7.16.3-1.zip.sha512>`__)

.. |WAZUH_KIBANA_7.17.0| replace:: `wazuh_kibana-|WAZUH_CURRENT|_7.17.0.zip <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/ui/kibana/wazuh_kibana-|WAZUH_CURRENT|_7.17.0-1.zip>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/checksums/wazuh/|WAZUH_CURRENT|/wazuh_kibana-|WAZUH_CURRENT|_7.17.0-1.zip.sha512>`__)

.. |WAZUH_KIBANA_7.17.1| replace:: `wazuh_kibana-|WAZUH_CURRENT|_7.17.1.zip <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/ui/kibana/wazuh_kibana-|WAZUH_CURRENT|_7.17.1-1.zip>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/checksums/wazuh/|WAZUH_CURRENT|/wazuh_kibana-|WAZUH_CURRENT|_7.17.1-1.zip.sha512>`__)

.. |WAZUH_KIBANA_7.17.2| replace:: `wazuh_kibana-|WAZUH_CURRENT|_7.17.2.zip <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/ui/kibana/wazuh_kibana-|WAZUH_CURRENT|_7.17.2-1.zip>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/checksums/wazuh/|WAZUH_CURRENT|/wazuh_kibana-|WAZUH_CURRENT|_7.17.2-1.zip.sha512>`__)

.. |WAZUH_KIBANA_7.17.3| replace:: `wazuh_kibana-|WAZUH_CURRENT|_7.17.3.zip <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/ui/kibana/wazuh_kibana-|WAZUH_CURRENT|_7.17.3-1.zip>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/checksums/wazuh/|WAZUH_CURRENT|/wazuh_kibana-|WAZUH_CURRENT|_7.17.3-1.zip.sha512>`__)

.. |WAZUH_KIBANA_7.17.4| replace:: `wazuh_kibana-|WAZUH_CURRENT|_7.17.4.zip <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/ui/kibana/wazuh_kibana-|WAZUH_CURRENT|_7.17.4-1.zip>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR|/checksums/wazuh/|WAZUH_CURRENT|/wazuh_kibana-|WAZUH_CURRENT|_7.17.4-1.zip.sha512>`__)

+------------------+-----------------------+--------------------------+
| Kibana Version   | Open Distro Version   | Package                  |
+==================+=======================+==========================+
| 7.10.2           | 1.13.2                | |WAZUH_KIBANA_7.10.2|    |
+------------------+-----------------------+--------------------------+
| 7.16.0           |                       | |WAZUH_KIBANA_7.16.0|    |
+------------------+-----------------------+--------------------------+
| 7.16.1           |                       | |WAZUH_KIBANA_7.16.1|    |
+------------------+-----------------------+--------------------------+
| 7.16.2           |                       | |WAZUH_KIBANA_7.16.2|    |
+------------------+-----------------------+--------------------------+
| 7.16.3           |                       | |WAZUH_KIBANA_7.16.3|    |
+------------------+-----------------------+--------------------------+
| 7.17.0           |                       | |WAZUH_KIBANA_7.17.0|    |
+------------------+-----------------------+--------------------------+
| 7.17.1           |                       | |WAZUH_KIBANA_7.17.1|    |
+------------------+-----------------------+--------------------------+
| 7.17.2           |                       | |WAZUH_KIBANA_7.17.2|    |
+------------------+-----------------------+--------------------------+
| 7.17.3           |                       | |WAZUH_KIBANA_7.17.3|    |
+------------------+-----------------------+--------------------------+
| 7.17.4           |                       | |WAZUH_KIBANA_7.17.4|    |
+------------------+-----------------------+--------------------------+

For a complete list of the available versions, see the `Wazuh Kibana plugin compatibility matrix <https://github.com/wazuh/wazuh-kibana-app/wiki/Compatibility>`_.

Wazuh Splunk app
----------------

For Wazuh Splunk app |WAZUH_SPLUNK_CURRENT|:

.. |SPLUNK_8.1.1_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.1.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.1-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.1-1.tar.gz.sha512>`__)

.. |SPLUNK_8.1.2_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.2.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.2-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.2-1.tar.gz.sha512>`__)

.. |SPLUNK_8.1.3_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.3.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.3-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.3-1.tar.gz.sha512>`__)

.. |SPLUNK_8.1.4_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.4.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.4-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.4-1.tar.gz.sha512>`__)

.. |SPLUNK_8.1.5_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.5.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.5-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.5-1.tar.gz.sha512>`__)

.. |SPLUNK_8.1.6_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.6.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.6-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.6-1.tar.gz.sha512>`__)

.. |SPLUNK_8.1.7_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.7.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.7-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.7-1.tar.gz.sha512>`__)

.. |SPLUNK_8.1.7.1_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.7.1.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.7.1-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.7.1-1.tar.gz.sha512>`__)

.. |SPLUNK_8.1.7.2_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.7.2.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.7.2-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.7.2-1.tar.gz.sha512>`__)

.. |SPLUNK_8.1.8_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.8.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.8-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.8-1.tar.gz.sha512>`__)

.. |SPLUNK_8.1.9_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.9.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.9-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.9-1.tar.gz.sha512>`__)

.. |SPLUNK_8.1.10_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.10.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.10-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.1.10-1.tar.gz.sha512>`__)

.. |SPLUNK_8.2.0_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.0.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.0-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.0-1.tar.gz.sha512>`__)

.. |SPLUNK_8.2.1_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.1.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.1-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.1-1.tar.gz.sha512>`__)

.. |SPLUNK_8.2.2_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.2.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.2-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.2-1.tar.gz.sha512>`__)

.. |SPLUNK_8.2.3_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.3.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.3-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.3-1.tar.gz.sha512>`__)

.. |SPLUNK_8.2.4_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.4.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.4-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.4-1.tar.gz.sha512>`__)

.. |SPLUNK_8.2.5_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.5.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.5-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.5-1.tar.gz.sha512>`__)

.. |SPLUNK_8.2.6_PKG| replace:: `wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.6.tar.gz <https://packages.wazuh.com/4.x/ui/splunk/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.6-1.tar.gz>`__ (`sha512 <https://packages.wazuh.com/4.x/checksums/wazuh/|WAZUH_SPLUNK_CURRENT|/wazuh_splunk-|WAZUH_SPLUNK_CURRENT|_8.2.6-1.tar.gz.sha512>`__)

+----------------------+----------------------+
| Splunk version       | Package              |
+======================+======================+
| 8.1.1                | |SPLUNK_8.1.1_PKG|   |
+----------------------+----------------------+
| 8.1.2                | |SPLUNK_8.1.2_PKG|   |
+----------------------+----------------------+
| 8.1.3                | |SPLUNK_8.1.3_PKG|   |
+----------------------+----------------------+
| 8.1.4                | |SPLUNK_8.1.4_PKG|   |
+----------------------+----------------------+
| 8.1.5                | |SPLUNK_8.1.5_PKG|   |
+----------------------+----------------------+
| 8.1.6                | |SPLUNK_8.1.6_PKG|   |
+----------------------+----------------------+
| 8.1.7                | |SPLUNK_8.1.7_PKG|   |
+----------------------+----------------------+
| 8.1.7.1              | |SPLUNK_8.1.7.1_PKG| |
+----------------------+----------------------+
| 8.1.7.2              | |SPLUNK_8.1.7.2_PKG| |
+----------------------+----------------------+
| 8.1.8                | |SPLUNK_8.1.8_PKG|   |
+----------------------+----------------------+
| 8.1.9                | |SPLUNK_8.1.9_PKG|   |
+----------------------+----------------------+
| 8.1.10               | |SPLUNK_8.1.10_PKG|  |
+----------------------+----------------------+
| 8.2.0                | |SPLUNK_8.2.0_PKG|   |
+----------------------+----------------------+
| 8.2.1                | |SPLUNK_8.2.1_PKG|   |
+----------------------+----------------------+
| 8.2.2                | |SPLUNK_8.2.2_PKG|   |
+----------------------+----------------------+
| 8.2.3                | |SPLUNK_8.2.3_PKG|   |
+----------------------+----------------------+
| 8.2.4                | |SPLUNK_8.2.4_PKG|   |
+----------------------+----------------------+
| 8.2.5                | |SPLUNK_8.2.5_PKG|   |
+----------------------+----------------------+
| 8.2.6                | |SPLUNK_8.2.6_PKG|   |
+----------------------+----------------------+

Filebeat
---------------

+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Package type | Package                                                                                                                                                                                                                                         |
+==============+=================================================================================================================================================================================================================================================+
|     RPM      | `filebeat-oss-|ELASTICSEARCH_LATEST|-x86_64.rpm <https://packages.wazuh.com/4.x/yum/filebeat-oss-|ELASTICSEARCH_LATEST|-x86_64.rpm>`_ (`sha512 <https://packages.wazuh.com/4.x/checksums/elasticsearch/|ELASTICSEARCH_LATEST|/filebeat-oss-|ELASTICSEARCH_LATEST|-x86_64.rpm.sha512>`__)                        |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|     DEB      | `filebeat-oss-|ELASTICSEARCH_LATEST|-amd64.deb <https://packages.wazuh.com/4.x/apt/pool/main/f/filebeat/filebeat-oss-|ELASTICSEARCH_LATEST|-amd64.deb>`_ (`sha512 <https://packages.wazuh.com/4.x/checksums/elasticsearch/|ELASTICSEARCH_LATEST|/filebeat-oss-|ELASTICSEARCH_LATEST|-amd64.deb.sha512>`__)      |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

Virtual machine
---------------

.. |VM_CentOS7_64_OVA| replace:: `wazuh-|WAZUH_CURRENT_OVA|.ova <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_OVA|/vm/wazuh-|WAZUH_CURRENT_OVA|.ova>`__ (`sha512 <https://packages.wazuh.com/|WAZUH_CURRENT_MAJOR_OVA|/checksums/wazuh/|WAZUH_CURRENT_OVA|/wazuh-|WAZUH_CURRENT_OVA|.ova.sha512>`__)

+--------------+--------------+--------------+---------+--------------------------------------+
| Distribution | Architecture | VM Format    | Version | Package                              |
+==============+==============+==============+=========+======================================+
|   CentOS 7   |    64bits    |      OVA     |  |WAZUH_CURRENT_OVA|  | |VM_CentOS7_64_OVA|                  |
+--------------+--------------+--------------+---------+--------------------------------------+

Amazon Machine Image
--------------------

.. |AMI_PRODUCT_PAGE| replace:: `Wazuh All-In-One Deployment <https://aws.amazon.com/marketplace/pp/prodview-eju4flv5eqmgq>`__

.. |var_WAZUH_CURRENT_AMI| replace:: |WAZUH_CURRENT_AMI|

+------------------+--------------+-------------+-------------------------+---------------------+
| Distribution     | Architecture | VM Format   | Latest version          | Product page        |
+==================+==============+=============+=========================+=====================+
| Amazon Linux 2   | 64-bit       | AWS AMI     | |var_WAZUH_CURRENT_AMI| | |AMI_PRODUCT_PAGE|  |
+------------------+--------------+-------------+-------------------------+---------------------+


MSU
---

+-------------------+--------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Version           | Architecture | Package                                                                                                                                                                                                                               |
+===================+==============+=======================================================================================================================================================================================================================================+
|  4.0.0 or later   |   32/64bits  | `msu-updates.json.gz <https://feed.wazuh.com/vulnerability-detector/windows/msu-updates.json.gz>`_ (`sha256 <https://feed.wazuh.com/vulnerability-detector/windows/msu-updates.meta>`__)                                              |
+-------------------+--------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
