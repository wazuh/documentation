###############################################################################
#
# Custom replacements
#
# This file contains the dictionary of custom replacements. Requires the 
# variables 'version', 'release' and 'is_latest_release' from 
# source/_variables/settings.py
#

import sys
import os
sys.path.append(os.path.abspath("_variables"))
from settings import version, is_latest_release, release


custom_replacements = {
    "|WAZUH_LATEST|" : "3.9.5",
    "|WAZUH_LATEST_MINOR|" : "3.9",
    "|WAZUH_LATEST_ANSIBLE|" : "3.9.5",
    "|WAZUH_LATEST_KUBERNETES|" : "3.9.5",
    "|WAZUH_LATEST_PUPPET|" : "3.9.5",
    "|WAZUH_LATEST_OVA|" : "3.9.5",
    "|WAZUH_LATEST_DOCKER|" : "3.9.5",
    "|ELASTICSEARCH_LATEST|" : "7.3.0",
    "|ELASTICSEARCH_LATEST_OVA|" : "7.3.0",
    "|ELASTICSEARCH_LATEST_ANSIBLE|" : "7.3.0",
    "|ELASTICSEARCH_LATEST_KUBERNETES|" : "7.3.0",
    "|ELASTICSEARCH_LATEST_PUPPET|" : "7.3.0",
    "|ELASTICSEARCH_LATEST_DOCKER|" : "7.3.0",
    "|SPLUNK_LATEST|" : "7.3.0",
    "|ELASTIC_6_LATEST|" : "6.8.8",
    "|WAZUH_REVISION_AIX|" : "1",
    "|WAZUH_REVISION_YUM_AGENT_I386|" : "1",
    "|WAZUH_REVISION_YUM_MANAGER_I386|" : "1",
    "|WAZUH_REVISION_YUM_AGENT_X86|" : "1",
    "|WAZUH_REVISION_YUM_MANAGER_X86|" : "1",
    "|WAZUH_REVISION_YUM_API_X86|" : "1",
    "|WAZUH_REVISION_YUM_AGENT_AARCH64|" : "1",
    "|WAZUH_REVISION_YUM_MANAGER_AARCH64|" : "1",
    "|WAZUH_REVISION_YUM_API_AARCH64|" : "1",
    "|WAZUH_REVISION_YUM_AGENT_ARMHF|" : "1",
    "|WAZUH_REVISION_YUM_MANAGER_ARMHF|" : "1",
    "|WAZUH_REVISION_YUM_API_ARMHF|" : "1",
    "|WAZUH_REVISION_YUM_AGENT_I386_EL5|" : "1",
    "|WAZUH_REVISION_YUM_AGENT_X86_EL5|" : "1",
    "|WAZUH_REVISION_DEB_AGENT_I386|" : "1",
    "|WAZUH_REVISION_DEB_MANAGER_I386|" : "1",
    "|WAZUH_REVISION_DEB_AGENT_X86|" : "1",
    "|WAZUH_REVISION_DEB_MANAGER_X86|" : "1",
    "|WAZUH_REVISION_DEB_API_X86|" : "1",
    "|WAZUH_REVISION_DEB_AGENT_AARCH64|" : "1",
    "|WAZUH_REVISION_DEB_MANAGER_AARCH64|" : "1",
    "|WAZUH_REVISION_DEB_API_AARCH64|" : "1",
    "|WAZUH_REVISION_DEB_AGENT_ARMHF|" : "1",
    "|WAZUH_REVISION_DEB_MANAGER_ARMHF|" : "1",
    "|WAZUH_REVISION_DEB_API_ARMHF|" : "1",
    "|WAZUH_REVISION_HPUX|" : "1",
    "|WAZUH_REVISION_OSX|" : "1",
    "|WAZUH_REVISION_WINDOWS|" : "1",
    "|CHECKSUMS_URL|" : "https://packages.wazuh.com/3.x/checksums/",
    "|RPM_AGENT|" : "https://packages.wazuh.com/3.x/yum/wazuh-agent",
    "|RPM_MANAGER|" : "https://packages.wazuh.com/3.x/yum/wazuh-manager",
    "|RPM_API|" : "https://packages.wazuh.com/3.x/yum/wazuh-api",
    "|DEB_AGENT|" : "https://packages.wazuh.com/3.x/apt/pool/main/w/wazuh-agent/wazuh-agent",
    "|DEB_MANAGER|" : "https://packages.wazuh.com/3.x/apt/pool/main/w/wazuh-manager/wazuh-manager",
    "|DEB_API|" : "https://packages.wazuh.com/3.x/apt/pool/main/w/wazuh-api/wazuh-api"
}
