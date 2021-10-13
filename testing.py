from login import login
import json

def main():

    """
    Login to each device! Right now, these are static entries. 
    Eventually, find a way to read these in from a list or an Excel file, 
    or something like that. The best way would be to make an SQL call to a 
    database with the relevant information and devices, but nobody at my 
    current workplace wants to work with databases, so Excel it is.
    """
    
    # Static entries for devices.
    devices = {}
    devices["physicalDevice"] = ["192.168.0.1","443","admin","admin"]
    #devices[""] = ["ipAddress","port","username","password"]   
    # Call the "login" class from "login.py", and return active API sessions.
    sessions = login(devices)

    # Perform operations on each device, beginning here.
    for name,device in sessions.items():
        #print("Device Name:",name)

        """
            #Order
            #1. Set basic global settings
            #2. Create Interfaces
            #3. Create Address Objects
            #4. Create LDAP
            #5. Create VPN
            #6. Cleanup 
            #   (Create Local Admin, disable default)
            #   (Create API Users, add to hosts)
            #7. Tie into FortiManager
        """

        ################################
        # 1. Set basic global settings #
        ################################ 
        # Set basic settings
        payload = {
            'hostname':name,
            'alias':name,
            'tftp':'disable',
            'admin-https-redirect':'enable',
            'admin-maintainer':'disable',
            'admin-scp':'enable',
            'admin-telnet':'disable',
            'cfg-save':'automatic',
            'gui-certificates':'enable',
            'gui-date-format':'yyyy/MM/dd',
            'gui-date-time-source':'system',
            'gui-display-hostname':'enable',
            'gui-firmware-upgrade-warning':'disable',
            'gui-display-hostname':'enable',
            'gui-ipv6':'disable',
            'gui-wireless-opensecurity':'disable',
            'language':'english',
            'lldp-reception':'disable',
            'lldp-transmission':'disable',
            'login-timestamp':'enable'
        }
        result = device.update_global(repr(payload))
        print(result)

        # Disable firmware & configuration auto-install
        payload = {
            'auto_install_config':'disable',
            'auto_install_image':'disable'
        }
        result = device.update_global_autoinstall(repr(payload))
        print(result)
        
        ########################
        # 2. Create interfaces #
        ########################

        payload = {
            'name':'Internal',
            'member':['lan3'],
            'type':'switch'
        }
        result = device.create_switch_interface(repr(payload))
        print(result)

        # Create API Admin Group
        #payload = {'name':'API_Admins','comments':'RestAPI Admin Profile','secfabgrp':'read-write','netgrp':'read-write','vpngrp':'read-write','fwgrp':'read-write','loggrp':'read-write','utmgrp':'read-write','wanoptgrp':'read-write','wifi':'read-write','ftviewgrp':'read-write','authgrp':'read-write','sysgrp':'read-write'}
        #result = device.create_API_Group(repr(payload))
        #print(result)

        # Get System Status
        status = device.get_system_status()
        print("Version:",status["version"])
        print("Build:",status["build"])
        print("Serial #:",status["serial"])

        # Get Interfaces
        #interfaces = device.get_interfaces()
        #for interface in interfaces:
            #print("Interface Name:",interface["name"])
            #print("Alias:", interface["alias"])
        #print("------******------")
        
        #print(interfaces)

        #print("------******------")

if __name__ == "__main__":
    main()
