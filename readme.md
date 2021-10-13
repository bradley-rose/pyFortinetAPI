# Fortigate REST API
This is a python library to use with the FortiOS REST API for FortiOS device management. I will only be testing this on FortiGate devices. 

There are a few tasks that I'd like to automate throughout the lifespan of these FortiGates:  
- Health checks: check logs and report back nicely. 
- Firmware upgrades: Backup the device configuration, print out the system firmware version, update the firmware, print out the system firmware version.
- General adoption of "infrastructure as code" or IaC. Storing the configuration as a Python script which is used as the primary running-configuration datastore. Any changes that apply to the standard configurations will be first appended to the relevant Python script, and then pushed to all devices simultaneously.
- That reminds me, reporting. I want some good output to confirm that each device was able to be communicated to successfully. Maybe colour code the console output, or just print out / email an HTML document to the person running the script with the results.

Nonetheless, this is a very simple implementation of the API thus far. I've only made a few custom API calls so far, but I intend to define modules for each possible action that can be pushed onto the FortiGates. This will supercede using SSH/HTTPS as the primary method of managing the individual devices.

## Using the API
Create a file that will act as a script. These are best categorized by role, or by device type. Example, you're going to want to group similar devices to keep as standard of a configuration as you can. So maybe create a device for a core device, and one for an access device. Or, in this case because this is Fortinet, a Spoke VPN device, and a Hub VPN device.

You're going to want to develop a way to login as well. I'll just do a static entry here so you can see how that might work, but I would recommend developing an inventory system, or using an IPAM system if available.

```py
from login import login

def main():

    # Creating device dictionary. Find a way to implement an inventory here.
    devices = {}

    # Static variables
    hostname = "deviceHostname"
    ipAddr = "10.69.69.69"
    port = "443"
    username = "admin"
    password = "admin"

    # Add to dictionary
    devices[hostname] = [ipAddr,port,username,password]

    # Get API objects that you can manipulate by "logging in".
    sessions = login(devices)

    # To manipulate each device:
    for name,device in sessions.items():
        
        # Call the "get_system_status()" module from the API.
        status = device.get_system_status()
        print("Version:",status["version"])
        print("Build:",status["build"])
        print("Serial #:",status["serial"])
```