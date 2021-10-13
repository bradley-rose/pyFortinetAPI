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

    hostname = "BradleyHomeGateway"
    ipAddr = "10.69.10.254"
    port = "443"
    username = "Bradley Rose"
    password = "J7*bL2f!Om2mlN3F$gJY"

    devices[hostname] = [
        ipAddr, 
        port, 
        username,
        password
    ]
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
            'admin-telnet-port':'23',
            'gui-wireless-opensecurity':'disable',
            'language':'english',
            'lldp-reception':'disable',
            'lldp-transmission':'disable',
            'login-timestamp':'enable'
        }
        result = device.update_global_settings(repr(payload))
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
        """
        payload = {
            'name':'Internal',
            'member':['lan3'],
            'type':'switch'
        }
        result = device.create_switch_interface(repr(payload))
        print(result)
        """

        # Get System Status
        status = device.get_system_status()
        print("Version:",status["version"])
        print("Build:",status["build"])
        print("Serial #:",status["serial"])

        result = device.get_ipsec_vpn_status()
        print(result)

        # Get Interfaces
        interfaces = device.get_interfaces()
        for interface in interfaces:
            print("Interface Name:",interface["name"])
            print("Alias:", interface["alias"])
        print("------******------")
        
        print(device.get_interface("lan2"))

        print("------******------")

if __name__ == "__main__":
    main()
