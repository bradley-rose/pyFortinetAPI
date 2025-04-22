__author__ = "Bradley Rose"
__version__ = "Last tested: FortiOS v7.2.x"
__date__ = "Last modified: April 2025"
__link__ = "https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/"

import requests
requests.packages.urllib3.disable_warnings() 

class FortiGate:
    def __init__(self, **kwargs):
        self.hostAddress = "192.168.1.99"
        self.port = 443
        self.firstLogin = False
        self.apiKey = None
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.headers = {}
        self.session = requests.Session()
        self.urlBase = "https://" + self.hostAddress + ":" + str(self.port) + "/"

    def __enter__(self):
        if self.apiKey:
            self.session.headers.update({'Authorization': 'Bearer ' + self.apiKey})
            return self
        else:
            self.login()
            return self
    
    def __exit__(self, *args):
        self.logout()

    def get(self, *, uri: str):
        """
        GET operation on provided API endpoint.
        :param uri: GET endpoint
        :return: Result if successful, HTTP status code otherwise (type int)
        """
        return self.session.get(
            self.urlBase + uri, 
            verify=False,
            timeout=10
        )

    def post(self, *, uri: str, payload: dict):
        """
        POST operation on provided API endpoint.
        :param uri: POST endpoint
        :param payload: Python dictionary containing payload.
        :return: HTTP status code.
        """
        try:
            return self.session.post(
                self.urlBase + uri, 
                json=payload,
                verify=False,
                timeout=10
            )
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError) as e:
            return e

    def delete(self, *, uri: str):
        """
        HTTP DELETE operation on provided API endpoint.
        :param uri: DELETE endpoint
        :result: HTTP status code.
        """
        try:
            return self.session.delete(
                self.urlBase + uri, 
                verify=False,
                timeout=10
            )
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError) as e:
            return e

    def put(self, *, uri: str, payload: dict):
        """
        PUT operation on provided API endpoint.
        :param uri: PUT endpoint
        :param payload: Python dictionary containing payload.
        :return: HTTP status code.
        """      
        try:
            return self.session.put(
                self.urlBase + uri, 
                json=payload,
                verify=False,
                timeout=10
            )
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError) as e:
            return e

    def login(self):
        """
        Initialize an API session to the FortiGate.
        """

        if self.firstLogin:
            result = self.post(
                uri = "api/v2/authentication",
                payload = {
                    "username": self.username,
                    "secretkey": "",
                    "new_password1": self.password,
                    "new_password2": self.password
                }
            )

        result = self.post(
            uri = "api/v2/authentication",
            payload = {
                "username": self.username,
                "secretkey": self.password
            }
        )

        for cookie in result.cookies:
            if "ccsrf" in cookie.name:
                self.session.headers.update({"X-CSRFTOKEN":cookie.value[1:-1]})

        return result

    def logout(self):
        """
        Delete API session to the FortiGate.
        """
        result = self.delete(
            uri = "api/v2/authentication"
        )
        return result

    def createSystemAdministrator(self, *, payload: dict):
        """
        Create a new local system administrator.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """
        result = self.post(
            uri = "api/v2/cmdb/system/admin",
            payload = payload
        )
        return result
    
    def deleteSystemAdministrator(self, *, name: str):
        """
        Delete an existing local system administrator.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.delete(
            uri = "api/v2/cmdb/system/admin/" + name
        )
        return result

    def updateSystemGlobal(self, *, payload: dict):
        """
        Update the system global configuration.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.put(
            uri = "api/v2/cmdb/system/global",
            payload = payload
        )
        return result
    
    def updateSystemSettings(self, *, payload: dict):
        """
        Update the system settings.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.put(
            uri = "api/v2/cmdb/system/settings",
            payload = payload
        )
        return result
    
    def updatePasswordPolicy(self, *, payload: dict):
        """
        Update the system password policy.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.put(
            uri = "api/v2/cmdb/system/password-policy",
            payload = payload
        )
        return result
    
    def deleteDhcpServer(self, *, id: int):
        """
        Delete a DHCP server object.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.delete(
            uri = "api/v2/cmdb/system.dhcp/server/" + str(id)
        )
        return result
    
    def createDhcpServer(self, *, payload: dict):
        """
        Create a DHCP server object.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.post(
            uri = "api/v2/cmdb/system.dhcp/server",
            payload = payload
        )
        return result
    
    def updateInterface(self, *, payload: dict):
        """
        Update a network interface.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.put(
            uri = "api/v2/cmdb/system/interface/" + payload["name"],
            payload = payload
        )
        return result
    
    def deleteInterface(self, *, name: str):
        """
        Delete a network interface.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.delete(
            uri = "api/v2/cmdb/system/interface/" + name
        )
        return result
    
    def updateSnmpSysinfo(self, *, payload: dict):
        """
        Update SNMP system information.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/ 
        """

        result = self.put(
            uri = "api/v2/cmdb/system.snmp/sysinfo",
            payload = payload
        )
        return result
    
    def createSnmpUser(self, *, payload: dict):
        """
        Update SNMP system information.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/ 
        """

        result = self.post(
            uri = "api/v2/cmdb/system.snmp/user",
            payload = payload
        )
        return result
    
    def updateSystemDns(self, *, payload: dict):
        """
        Update system DNS configuration.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/ 
        """

        result = self.put(
            uri = "api/v2/cmdb/system/dns",
            payload = payload
        )
        return result
    
    def updateSystemNtp(self, *, payload: dict):
        """
        Update system NTP configuration.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/ 
        """

        result = self.put(
            uri = "api/v2/cmdb/system/ntp",
            payload = payload
        )
        return result
    
    def createFirewallAddress(self, *, payload: dict):
        """
        Create firewall address object
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/firewall/
        """

        result = self.post(
            uri = "api/v2/cmdb/firewall/address",
            payload = payload
        )
        return result
    
    def createFirewallGroup(self, *, payload: dict):
        """
        Create firewall address group object
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/firewall/
        """

        result = self.post(
            uri = "api/v2/cmdb/firewall/addrgrp",
            payload = payload
        )
        return result
    
    def createVpnIpsecPhase1Interface(self, *, payload: dict):
        """
        Create VPN IPsec Phase 1 Interface
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/vpn/
        """

        result = self.post(
            uri = "api/v2/cmdb/vpn.ipsec/phase1-interface",
            payload = payload
        )
        return result
    
    def updateVpnIpsecPhase1Interface(self, *, payload: dict):
        """
        Update VPN IPsec Phase 1 Interface
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/vpn/
        """

        result = self.put(
            uri = "api/v2/cmdb/vpn.ipsec/phase1-interface/" + payload["name"],
            payload = payload
        )
        return result

    def createVpnIpsecPhase2Interface(self, *, payload: dict):
        """
        Create VPN IPsec Phase 2 Interface
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/vpn/
        """

        result = self.post(
            uri = "api/v2/cmdb/vpn.ipsec/phase2-interface",
            payload = payload
        )
        return result
    
    def createSystemZone(self, *, payload: dict):
        """
        Create system zone interface for interface grouping / zone-based firewalling.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.post(
            uri = "api/v2/cmdb/system/zone",
            payload = payload
        )
        return result
    
    def deleteFirewallPolicy(self, *, id: int):
        """
        Delete existing firewall policy.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/firewall/
        """

        result = self.delete(
            uri = "api/v2/cmdb/firewall/policy/" + str(id)
        )
        return result
    
    def createFirewallPolicy(self, *, payload: dict):
        """
        Create new firewall policy
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/firewall/
        """

        result = self.post(
            uri = "api/v2/cmdb/firewall/policy",
            payload = payload
        )
        return result
    
    def createStaticRoute(self, *, payload: dict):
        """
        Create new static route
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/router/
        """

        result = self.post(
            uri = "api/v2/cmdb/router/static",
            payload = payload
        )
        return result
    
    def updateVirtualSwitch(self, *, payload: dict):
        """
        Update FortiGate virtual switch
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.put(
            uri = "api/v2/cmdb/system/virtual-switch/" + payload["name"],
            payload = payload
        )
        return result
    
    def createTacacsUser(self, *, payload: dict):
        """
        Create TACACS user object
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/user/
        """

        result = self.post(
            uri = "api/v2/cmdb/user/tacacs+",
            payload = payload
        )
        return result
    
    def updateTacacsUser(self, *, payload: dict):
        """
        Update TACACS user object
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/user/
        """

        result = self.put(
            uri = "api/v2/cmdb/user/tacacs+/" + payload["name"],
            payload = payload
        )
        return result
    
    def createUserGroup(self, *, payload: dict):
        """
        Create user group object
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/user/
        """

        result = self.post(
            uri = "api/v2/cmdb/user/group",
            payload = payload
        )
        return result
    
    def getUserGroup(self, *, name: str):
        """
        Get user group object
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/user/
        """

        result = self.get(
            uri = "api/v2/cmdb/user/group/" + name
        )
        return result
        
    
    def createSystemAccprofile(self, *, payload: dict):
        """
        Create system accprofile
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.post(
            uri = "api/v2/cmdb/system/accprofile",
            payload = payload
        )
        return result
    
    def getSystemCentralManagement(self):
        """
        Get central management configuration.
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.get(
            url = "api/v2/cmdb/system/central-management"
        )
        return result
    
    def updateSystemCentralManagement(self, *, payload: dict):
        """
        Update central management settings
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.put(
            uri = "api/v2/cmdb/system/central-management",
            payload = payload
        )
        return result
    
    def updateLogFortianalyzerSettings(self, *, payload: dict):
        """
        Update log Fortianalyzer settings
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/log/
        """

        result = self.put(
            uri = "api/v2/cmdb/log.fortianalyzer/setting",
            payload = payload
        )
        return result
    
    def updateSystemFortiguard(self, *, payload: dict):
        """
        Update FortiGuard settings
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.put(
            uri = "api/v2/cmdb/system/fortiguard",
            payload = payload
        )
        return result
    
    def updateLogSettings(self, *, payload: dict):
        """
        Update FortiGuard settings
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/log/
        """

        result = self.put(
            uri = "api/v2/cmdb/log/setting",
            payload = payload
        )
        return result
    
    def getInterfaces(self):
        """
        Obtain list of system interfaces
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.get(
            uri = "api/v2/cmdb/system/interface"
        )
        return result
    
    def createSystemReplacementMessageImage(self, *, payload: dict):
        """
        Obtain list of system interfaces
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.post(
            uri = "api/v2/cmdb/system/replacemsg-image",
            payload = payload
        )
        return result

    def updateSystemReplacementMessageAuth(self, *, type: str, payload: dict):
        """
        Obtain list of system interfaces
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/system/
        """

        result = self.put(
            uri = "api/v2/cmdb/system.replacemsg/auth/" + type,
            payload = payload
        )
        return result
    
    def createVpnCertificateLocal(self, *, payload: dict):
        """
        Create VPN local certificates
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/vpn/
        """

        result = self.post(
            uri = "api/v2/cmdb/vpn.certificate/local",
            payload = payload
        )
        return result
    
    def updateUserSetting(self, *, payload: dict):
        """
        Update user settings
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/user/
        """

        result = self.put(
            uri = "api/v2/cmdb/user/setting",
            payload = payload
        )
        return result
    
    def createUserLdap(self, *, payload: dict):
        """
        Create LDAP server object
        API specification: https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/3684/1/user/
        """

        result = self.post(
            uri = "api/v2/cmdb/user/ldap",
            payload = payload
        )
        return result
