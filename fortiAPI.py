#!/usr/bin/env Python
__author__ = "James Simpson"
__copyright__ = "Copyright 2017, James Simpson"
__license__ = "MIT"
__version__ = "0.2.1"

import requests
import logging

# Disable requests' warnings for insecure connections
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class FortiGate:
    def __init__(self, ipaddr,networkAddress,username,password,region,connectionType="dhcp",timeout=10,vdom="root",port="443"):

        self.ipaddr = ipaddr
        self.username = username
        self.password = password
        self.port = port
        self.urlbase = "https://{ipaddr}:{port}/".format(ipaddr=self.ipaddr,port=self.port)
        self.timeout = timeout
        self.vdom = vdom
        self.networkAddress = networkAddress
        self.region = region
        self.connectionType = connectionType

    # Login / Logout Handlers
    def login(self):
        """
        Log in to FortiGate with info provided in during class instantiation
        :return: Open Session
        """
        session = requests.session()
        url = self.urlbase + 'logincheck'

        # Login
        session.post(url,
                     data='username={username}&secretkey={password}'.format(username=self.username,
                                                                            password=self.password),
                     verify=False,
                     timeout=self.timeout)

        # Get CSRF token from cookies, add to headers
        for cookie in session.cookies:
            if cookie.name == 'ccsrftoken':
                csrftoken = cookie.value[1:-1]  # strip quotes
                session.headers.update({'X-CSRFTOKEN': csrftoken})

        # Check whether login was successful
        login_check = session.get(self.urlbase + "api/v2/cmdb/system/vdom")
        login_check.raise_for_status()
        return session

    def logout(self, session):
        """
        Log out of device
        :param session: Session created by login method
        :return: None
        """
        url = self.urlbase + 'logout'
        session.get(url, verify=False, timeout=self.timeout)
        logging.info("Session logged out.")

    # General Logic Methods
    def does_exist(self, object_url):
        """
        GET URL to assert whether it exists within the firewall
        :param object_url: Object to locate
        :return: Bool - True if exists, False if not
        """
        session = self.login()
        request = session.get(object_url, verify=False, timeout=self.timeout, params='vdom='+self.vdom)
        self.logout(session)        
        if request.status_code == 200:
            return True
        else:
            return False

    # API Interaction Methods
    def get(self, url):
        """
        Perform GET operation on provided URL
        :param url: Target of GET operation
        :return: Request result if successful (type list), HTTP status code otherwise (type int)
        """
        session = self.login()
        request = session.get(url, verify=False, timeout=self.timeout, params='vdom='+self.vdom)
        self.logout(session)
        if request.status_code == 200:
            return request.json()['results']
        else:
            return request.status_code

    def put(self, url, data):
        """
        Perform PUT operation on provided URL
        :param url: Target of PUT operation
        :param data: JSON data. MUST be a correctly formatted string. e.g. "{'key': 'value'}"
        :return: HTTP status code returned from PUT operation
        """
        session = self.login()
        result = session.put(url, data=data, verify=False, timeout=self.timeout, params='vdom='+self.vdom).status_code
        self.logout(session)
        return result

    def post(self, url, data):
        """
        Perform POST operation on provided URL
        :param url: Target of POST operation
        :param data: JSON data. MUST be a correctly formatted string. e.g. "{'key': 'value'}"
        :return: HTTP status code returned from POST operation
        """
        session = self.login()
        result = session.post(url, data=data, verify=False, timeout=self.timeout, params='vdom='+self.vdom).status_code
        self.logout(session)
        return result

    def delete(self, url):
        """
        Perform DELETE operation on provided URL
        :param url: Target of DELETE operation
        :return: HTTP status code returned from DELETE operation
        """
        session = self.login()
        result = session.delete(url, verify=False, timeout=self.timeout, params='vdom='+self.vdom).status_code
        self.logout(session)
        return result

    # Firewall Address Methods
    def get_firewall_address(self, specific=False, filters=False):
        """
        Get address object information from firewall
        :param specific: If provided, a specific object will be returned. If not, all objects will be returned.
        :param filters: If provided, the raw filter is appended to the API call.
        :return: JSON data for all objects in scope of request, nested in a list.
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/address/"
        if specific:
            api_url += specific
        elif filters:
            api_url += "?filter=" + filters
        results = self.get(api_url)
        return results

    def create_firewall_address(self, address, data):
        """
        Create firewall address record
        :param address: Address record to be created
        :param data: JSON Data with which to create the address record
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/address/"
        # Check whether target object already exists
        if not self.does_exist(api_url + address):
            self.post(api_url, repr(data))
            return '\x1b[1;32;40m' + ("Created firewall address: " + address) + '\x1b[0m'
               
        api_url += str(address)
        same=True
        diffVar = self.get(api_url)[0]

        for key,value in data.items():
            if not value == diffVar[key]:
                same=False
        if not (same):
            self.put(api_url, repr(data))
            return '\x1b[1;32;40m' + ("Updated interface: " + address) + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ('No changes to ' + address + ' necessary.') + '\x1b[0m'
            

    def delete_firewall_address(self, address):
        """
        Delete firewall address record
        :param address: Address record to be deleted
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/address/" + address
        result = self.delete(api_url)
        return result

    # Address Group Methods
    def get_address_group(self, specific=False, filters=False):
        """
        Get address group object information from firewall
        :param specific: If provided, a specific object will be returned. If not, all objects will be returned.
        :param filters: If provided, the raw filter is appended to the API call.
        :return: JSON data for all objects in scope of request, nested in a list.
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/addrgrp/"
        if specific:
            api_url += specific
        elif filters:
            api_url += "?filter=" + filters
        results = self.get(api_url)
        return results

    def create_address_group(self, group_name, data):
        """
        Create address group
        :param group_name: Address group to be created
        :param data: JSON Data with which to create the address group
        :return: HTTP Status Code.
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/addrgrp/"
        if not self.does_exist(api_url + group_name):
            self.post(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Created firewall address group: " + group_name) + '\x1b[0m'

        api_url += str(group_name)
        same=True
        diffVar = self.get(api_url)[0]

        for key,value in data.items():
            if not value == diffVar[key]:
                same=False
        if not (same):
            self.put(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Updated interface: " + group_name) + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ('No changes to ' + group_name + ' necessary.') + '\x1b[0m'

    def delete_address_group(self, group_name):
        """
        Delete firewall address group
        :param group_name: Address group to be deleted
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/addrgrp/" + group_name
        result = self.delete(api_url)
        return result

    # Service Category Methods
    def get_service_category(self, specific=False, filters=False):
        """
        Get service category information from firewall
        :param specific: If provided, a specific object will be returned. If not, all objects will be returned.
        :param filters: If provided, the raw filter is appended to the API call.
        :return: JSON data for all objects in scope of request, nested in a list.
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall.service/category/"
        if specific:
            api_url += specific
        elif filters:
            api_url += "?filter=" + filters
        results = self.get(api_url)
        return results

    def update_service_category(self, category, data):
        """
        Update service category with provided data.
        :param category: Service category being updated
        :param data: JSON Data with which to upate the service category
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall.service/category/" + category
        # Check whether target object already exists
        if not self.does_exist(api_url):
            logging.error('Requested service category "{category}" does not exist in Firewall config.'.format(
                category=category))
            return 404
        result = self.put(api_url, data)
        return result

    def create_service_category(self, category, data):
        """
        Create service category
        :param category: Service category to be created
        :param data: JSON Data with which to create the service category
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall.service/category/"
        if self.does_exist(api_url + category):
            return 424
        result = self.post(api_url, data)
        return result

    def delete_service_category(self, category):
        """
        Delete firewall service category
        :param category: Service categrory to be deleted
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall.service/category/" + category
        result = self.delete(api_url)
        return result

    # Service Group Methods
    def get_service_group(self, specific=False, filters=False):
        """
        Get service group information from firewall
        :param specific: If provided, a specific object will be returned. If not, all objects will be returned.
        :param filters: If provided, the raw filter is appended to the API call.
        :return: JSON data for all objects in scope of request, nested in a list.
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall.service/group/"
        if specific:
            api_url += specific
        elif filters:
            api_url += "?filter=" + filters
        results = self.get(api_url)
        return results

    def update_service_group(self, group_name, data):
        """
        Update service group with provided data
        :param group_name: Service group being updated
        :param data: JSON Data with which to upate the service group
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall.service/group/" + group_name
        # Check whether target object already exists
        if not self.does_exist(api_url):
            logging.error('Requested service group "{group_name}" does not exist in Firewall config.'.format(
                group_name=group_name))
            return 404
        result = self.put(api_url, data)
        return result

    def create_service_group(self, group_name, data):
        """
        Create service group
        :param group_name: Service group to be created
        :param data: JSON Data with which to create the service group
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall.service/group/"
        if self.does_exist(api_url + group_name):
            return 424
        result = self.post(api_url, data)
        return result

    def delete_service_group(self, group_name):
        """
        Delete firewall service group
        :param group_name: Service categrory to be deleted
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall.service/group/" + group_name
        result = self.delete(api_url)
        return result

    # Firewall Service Methods
    def get_firewall_service(self, specific=False, filters=False):
        """
        Get service object information from firewall
        :param specific: If provided, a specific object will be returned. If not, all objects will be returned.
        :param filters: If provided, the raw filter is appended to the API call.
        :return: JSON data for all objects in scope of request, nested in a list.
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall.service/custom/"
        if specific:
            api_url += specific
        elif filters:
            api_url += "?filter=" + filters
        results = self.get(api_url)
        return results

    def update_firewall_service(self, service_name, data):
        """
        Update service with provided data
        :param service_name: Service  being updated
        :param data: JSON Data with which to upate the service
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall.service/custom/" + service_name
        # Check whether target object already exists
        if not self.does_exist(api_url):
            logging.error('Requested service "{service_name}" does not exist in Firewall config.'.format(
                service_name=service_name))
            return 404
        result = self.put(api_url, data)
        return result

    def create_firewall_service(self, service_name, data):
        """
        Create service
        :param service_name: Service to be created
        :param data: JSON Data with which to create the service
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall.service/custom/"
        if self.does_exist(api_url + service_name):
            return 424
        result = self.post(api_url, data)
        return result

    def delete_firewall_service(self, service_name):
        """
        Delete firewall service
        :param service_name: Service categrory to be deleted
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall.service/custom/" + service_name
        result = self.delete(api_url)
        return result

    # Firewall Policy Methods
    def get_firewall_policy(self, specific=False, filters=False):
        """
        Get firewall policy information from firewall
        :param specific: If provided, a specific object will be returned. If not, all objects will be returned.
            Specific can either be the policy name, or the policy ID.
        :param filters: If provided, the raw filter is appended to the API call.
        :return: JSON data for all objects in scope of request, nested in a list.
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/policy/"
        if specific:
            if type(specific) == int:
                api_url += str(specific)
            else:
                api_url += "?filter=name==" + specific
        elif filters:
            api_url += "?filter=" + filters
        results = self.get(api_url)
        if type(results) == int:
            return results
        elif len(results) == 0:
            return 404
        else:
            return results

    def update_firewall_policy(self, policy_id, data):
        """
        Update firewall policy with provided data
        :param policy_id: ID of firewall policy to be updated
        :param data: Data with which to update the firewall policy
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/policy/" + str(policy_id)
        # Check whether target object already exists
        if not self.does_exist(api_url):
            logging.error('Requested Policy ID {policy_id} does not exist in Firewall Config.'.format(
                policy_id=str(policy_id)))
            return 404
        result = self.put(api_url, data)
        return result

    def move_firewall_policy(self, policy_id, position, neighbour):
        """
        Move firewall policy to new location
        :param policy_id: ID of firewall policy being moved
        :param position: "before" or "after"
        :param neighbour: ID of policy being used as positional reference
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/policy/" + str(policy_id)
        data = "{{'action': 'move', '{position}': {neighbour}}}".format(position=position, neighbour=neighbour)
        result = self.put(api_url, data)
        return result

    def create_firewall_policy(self, policy_id, data):
        """
        Create firewall Policy
        :param policy_id: ID of policy to be created
        :param data: Data with which to create policy
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/policy/"
        # Check whether object already exists
        if not self.does_exist(api_url + str(policy_id)):
            self.post(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Created firewall policy: " + data['name']) + '\x1b[0m'

        api_url += str(policy_id)
        same=True
        diffVar = self.get(api_url)[0]
        
        for key,value in data.items():
            if not value == diffVar[key]:
                same=False
        if not (same):
            self.put(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Updated firewall policy: " + data['name']) + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ('No changes to firewall policy' + data['name'] + ' necessary.') + '\x1b[0m'


    def delete_firewall_policy(self, policy_id):
        """
        Delete firewall policy
        :param policy_id: ID of policy to be deleted
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/policy/" + str(policy_id)
        result = self.delete(api_url)
        return result

    # SNMPv2 Community Methods
    def get_snmp_community(self, specific=False, filters=False):
        """
        Get SNMP community information from firewall
        :param specific: If provided, a specific object will be returned. If not, all objects will be returned.
            Specific can either be the Community string, or its internal ID.
        :param filters: If provided, the raw filter is appended to the API call.
        
        :return: JSON data for all objects in scope of request, nested in a list.
        """
        api_url = self.urlbase + "api/v2/cmdb/system.snmp/community/"
        if specific:
            if type(specific) == int:
                api_url += str(specific)
            else:
                api_url += "?filter=name==" + specific
        elif filters:
            api_url += "?filter=" + filters
        results = self.get(api_url)
        return results

    def update_snmp_community(self, community_id, data):
        """
        Update SNMP community with provided data
        :param community_id: ID of community  being updated
        :param data: JSON Data with which to update the community
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/system.snmp/community/" + str(community_id)
        # Check whether target object already exists
        if not self.does_exist(api_url):
            logging.error('Requested SNMP Community ID "{community_id}" does not exist in Firewall config.'.format(
                community_id=community_id))
            return 404
        result = self.put(api_url, data)
        return result

    def create_snmp_community(self, community_id, data):
        """
        Create SNMP community
        :param community_id: ID of the SNMP Community to be created
        :param data: JSON Data with which to create the SNMP community
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/system.snmp/community/"
        if self.does_exist(api_url + str(community_id)):
            return 424
        result = self.post(api_url, data)
        return result

    def delete_snmp_community(self, community_id):
        """
        Delete SNMP community
        :param community_id: ID of the SNMP Community to be deleted
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/system.snmp/community/" + str(community_id)
        result = self.delete(api_url)
        return result

    # ISDB read
    def get_internet_services(self, specific=False, filters=False):
        """
        Get ISDB (internet services database)
        :param specific: If provided, a specific object will be returned. 
        :param filters: If provided, the raw filter is appended to the API call.
        
        :return: JSON data for all objects in scope of request, nested in a list.
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/internet-service/"
        if specific:
            api_url += str(specific)
        elif filters:
            api_url += "?filter=" + filters
        results = self.get(api_url)
        return results

    
    def create_interface(self, interfaceName, data):
        """
        Update SNMP community with provided data
        :param community_id: ID of community  being updated
        :param data: JSON Data with which to update the community
        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/system/interface/"
        # Check whether target object already exists
        if not self.does_exist(api_url + str(interfaceName)):
            self.post(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Created interface: " + str(interfaceName)) + '\x1b[0m'
        
        api_url += str(interfaceName)
        same=True
        diffVar = self.get(api_url)[0]

        for key,value in data.items():
            if key == 'allowaccess':
                value = " ".join(sorted(data[key].split()))
                diffVar[key] = " ".join(sorted(diffVar[key].split()))
            if not value == diffVar[key]:
                same=False
        
        if not (same):
            self.put(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Updated interface: " + str(interfaceName)) + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ('No changes to ' + str(interfaceName) + ' necessary.') + '\x1b[0m'
      

    def get_interfaces(self, specific=False, filters=False):
        """
        Get just the names of the interfaces output into a list, and nothing more.
        """
        api_url = self.urlbase + "api/v2/cmdb/system/interface"
        if specific:
            api_url += '/' + specific
        elif filters:
            api_url += "?filter=" + filters
        results = self.get(api_url)
        return results

    def get_system_status(self):
        api_url = self.urlbase + "api/v2/cmdb/system/status"
        session = self.login()
        request = session.get(api_url, verify=False, timeout=self.timeout, params='vdom='+self.vdom)
        self.logout(session)

        if request.status_code == 200:
            return request.json()
        else:
            return request.status_code

    def get_ldap(self):
        api_url = self.urlbase + "api/v2/cmdb/user/ldap"
        results = self.get(api_url)
        if not results:
            logging.error('No LDAP configured on this device.')
            return "No LDAP Configured"
        results = self.get(api_url)
        return results[0]

    def update_global_settings(self, data):
        api_url = self.urlbase + "api/v2/cmdb/system/global"
        same=True
        diffVar = self.get(api_url)
        for key,value in data.items():
            if not value == diffVar[key]:
                same=False
        if not (same):
            self.put(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Updated global settings.") + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ('No changes to global settings necessary.') + '\x1b[0m'

    def get_global_settings(self):
        api_url = self.urlbase + "api/v2/cmdb/system/global"
        return self.get(api_url)

    def update_global_autoinstall(self, data):
        api_url = self.urlbase + "api/v2/cmdb/system/auto-install"
        same=True
        diffVar = self.get(api_url)

        for key,value in data.items():
            if not value == diffVar[key]:
                same=False
        if not (same):
            self.put(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Updated auto-installation settings.") + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ('No changes to autoinstall settings necessary.') + '\x1b[0m'

            
    def get_global_autoinstall(self):
        api_url = self.urlbase + "api/v2/cmdb/system/auto-install"
        return self.get(api_url)

    def get_switch_interface(self, interfaceName):
        api_url = self.urlbase + "api/v2/cmdb/system/switch-interface/" + str(interfaceName)
        if not self.does_exist(api_url):
            logging.error('Requested switch interface "{interface_Name}" does not exist.'.format(
                interface_Name=interfaceName))
            return 404
        results = self.get(api_url)
        return results

    def update_switch_interface(self, interfaceName, data):
        api_url = self.urlbase + "api/v2/cmdb/system/switch-interface/" + str(interfaceName)
        if not self.does_exist(api_url):
            logging.error('Requested switch interface "{interface_Name}" does not exist.'.format(
                interface_Name=interfaceName))
            return 404
        results = self.put(api_url, data)
        return results
    
    def create_dhcp_server(self, data):
        api_url = self.urlbase + "api/v2/cmdb/system.dhcp/server/"
        if not self.does_exist(api_url + str(data['id'])):
            self.post(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Created DHCP server for: " + data['interface']) + '\x1b[0m'

        api_url += str(data['id'])
        same=True
        diffVar = self.get(api_url)[0]
        for key,value in data.items():
            if not value == diffVar[key]:
                same=False
        if not (same):
            self.put(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Updated: " + str(data['interface']) + " DHCP settings.") + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ("No changes to " + str(data['interface']) + " DHCP settings necessary.") + '\x1b[0m'

    def get_dhcp_server(self, id):
        api_url = self.urlbase + "api/v2/cmdb/system.dhcp/server/" + str(id)
        if self.does_exist(api_url):
            return self.get(api_url)
        else:
            return False

    def update_dns_settings(self, data):
        api_url = self.urlbase + "api/v2/cmdb/system/dns"
        same=True
        diffVar = self.get(api_url)

        for key,value in data.items():
            if not value == diffVar[key]:
                same=False
        if not (same):
            self.put(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Updated system DNS settings.") + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ("No changes to DNS settings necessary.") + '\x1b[0m'


    def create_LDAP(self, ldapName, data):
        api_url = self.urlbase + "api/v2/cmdb/user/ldap/"
        if not self.does_exist(api_url + ldapName):
            self.post(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Created LDAP configuration: " + ldapName) + '\x1b[0m'

        api_url += ldapName
        same=True
        diffVar = self.get(api_url)[0]
        for key,value in data.items():
            if not value == diffVar[key]:
                if key == 'password':
                    continue
                else:
                    same=False
        if not (same):
            self.put(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Updated LDAP configuration: " + ldapName) + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ("No changes to LDAP configuration " + ldapName + " necessary.") + '\x1b[0m'

    def create_VPN_phase1(self,name,data):
        api_url = self.urlbase + "api/v2/cmdb/vpn.ipsec/phase1-interface/"
        if not self.does_exist(api_url + name):
            self.post(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Created VPN Phase I: " + name) + '\x1b[0m'

        api_url += name
        same=True
        diffVar = self.get(api_url)[0]
        for key,value in data.items():
            if not value == diffVar[key]:
                if key == 'psksecret' or 'signature-hash-alg':
                    continue
                else:
                    same=False
        if not (same):
            self.put(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Updated VPN Phase I configuration: " + name) + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ("No changes to VPN Phase I configuration " + name + " necessary.") + '\x1b[0m'


    def create_VPN_phase2(self,name,data):
        api_url = self.urlbase + "api/v2/cmdb/vpn.ipsec/phase2-interface/"
        if not self.does_exist(api_url + name):
            self.post(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Created VPN Phase II: " + name) + '\x1b[0m'

        api_url += name
        same=True
        diffVar = self.get(api_url)[0]
        for key,value in data.items():
            if not value == diffVar[key]:
                same=False
        if not (same):
            self.put(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Updated VPN Phase II configuration: " + name) + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ("No changes to VPN Phase II configuration " + name + " necessary.") + '\x1b[0m'

    def create_static_route(self,data):
        api_url = self.urlbase + "api/v2/cmdb/router/static/"
        if not self.does_exist(api_url + str(data['seq-num'])):
            self.post(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Created static route: " + data['comment']) + '\x1b[0m'

        api_url += str(data['seq-num'])
        same=True
        diffVar = self.get(api_url)[0]
        for key,value in data.items():
            if not value == diffVar[key]:
                same=False
        if not (same):
            self.put(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Updated static route: " + data['comment']) + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ("No changes to static route (" + data['comment'] + ") necessary.") + '\x1b[0m'

    def create_bgp_route(self, data):
        api_url = self.urlbase + "api/v2/cmdb/router/bgp"
        self.put(api_url, repr(data))
        return '\x1b[1;33;40m' + ("Set BGP configuration.") + '\x1b[0m'

    def get_bgp_route(self):
        api_url = self.urlbase + "api/v2/cmdb/router/bgp"
        return self.get(api_url)

    def get_antivirus_profile(self, name):
        api_url = self.urlbase + "api/v2/cmdb/antivirus/profile/" + name
        return self.get(api_url)

    def create_antivirus_profile(self, name, data):
        api_url = self.urlbase + "api/v2/cmdb/antivirus/profile/"

        if not self.does_exist(api_url + name):
            self.post(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Created antivirus profile: " + name) + '\x1b[0m'

        api_url += name
        same=True
        diffVar = self.get(api_url)[0]

        for key,value in data.items():
            if not value == diffVar[key]:
                same=False
        if not (same):
            self.put(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Updated antivirus profile route: " + name) + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ("No changes to " + name + "antivirus profile necessary.") + '\x1b[0m'

    def create_user_group(self,data):
        api_url = self.urlbase + "api/v2/cmdb/user/group/"

        if not self.does_exist(api_url + data['name']):
            self.post(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Created user group: " + data['name']) + '\x1b[0m'

        api_url += data['name']
        same=True
        diffVar = self.get(api_url)[0]
        diffVar['match'] = diffVar['match'].sort()
        data['match'] = data['match'].sort()

        for key,value in data.items():
            if not value == diffVar[key]:
                same=False
        if not (same):
            self.put(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Updated user group: " + data['name']) + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ("No changes to " + data['name'] + " user group necessary.") + '\x1b[0m'

    def create_admin(self,data):
        api_url = self.urlbase + "api/v2/cmdb/system/admin/"

        if not self.does_exist(api_url + data['name']):
            self.post(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Created administrator: " + data['name']) + '\x1b[0m'

        api_url += data['name']
        same=True
        diffVar = self.get(api_url)[0]

        for key,value in data.items():
            if not value == diffVar[key]:
                if key == 'password':
                    continue
                else:
                    same=False
        if not (same):
            self.put(api_url, repr(data))
            return '\x1b[1;33;40m' + ("Updated administrator: " + data['name']) + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ("No changes to " + data['name'] + " administrator.") + '\x1b[0m'

    def delete_admin(self, name):
        api_url = self.urlbase + "api/v2/cmdb/system/admin/" + name
        if self.does_exist(api_url):
            self.delete(api_url)
            return '\x1b[1;33;40m' + ("Administrator ",name,"has been deleted.") + '\x1b[0m'
        else:
            return '\x1b[1;32;40m' + ("Administrator does not exist.") + '\x1b[0m'

    def install_ca_certificate(self, data):
        api_url = self.urlbase + "api/v2/cmdb/certificate/ca/"
        if not self.does_exist(api_url + 'CA_Cert_1'):
            return self.post(api_url, repr(data))
            #return '\x1b[1;33;40m' + ("Installed CA Certificate: " + data['name']) + '\x1b[0m'
        
        return '\x1b[1;32;40m' + ("No changes made to existing certificate.") + '\x1b[0m'