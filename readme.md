# Fortigate REST API
This is a python library to use with the FortiOS REST API for FortiOS device management. I will only be testing this on FortiGate devices. 

There are a few tasks that I'd like to automate throughout the lifespan of these FortiGates:  
- Health checks: check logs and report back nicely. 
- Firmware upgrades: Backup the device configuration, print out the system firmware version, update the firmware, print out the system firmware version.
- General adoption of "infrastructure as code" or IaC. Storing the configuration as a Python script which is used as the primary running-configuration datastore. Any changes that apply to the standard configurations will be first appended to the relevant Python script, and then pushed to all devices simultaneously.
- That reminds me, reporting. I want some good output to confirm that each device was able to be communicated to successfully. Maybe colour code the console output, or just print out / email an HTML document to the person running the script with the results.

Nonetheless, this is a very simple implementation of the API thus far. I've only made a few custom API calls so far, but I intend to define modules for each possible action that can be pushed onto the FortiGates. This will supercede using SSH/HTTPS as the primary method of managing the individual devices.

