from login import login

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
    devices[""] = ["ipAddress","port","username","password"]
    devices[""] = ["ipAddress","port","username","password"]   
    # Call the "login" class from "login.py", and return active API sessions.
    sessions = login(devices)

    # Perform operations on each device, beginning here.
    for name,device in sessions.items():
        #print("Device Name:",name)

        # Get System Status
        status = device.get_system_status()
        print("Version:",status["version"])
        print("Build:",status["build"])
        print("Serial #:",status["serial"])

        # Get Interfaces
        interfaces = device.get_interfaces()
        for interface in interfaces:
            print("Interface Name:",interface["name"])
            print("Alias:", interface["alias"])
        print("------******------")
        
        print(device.get_ldap())

        print("------******------")

if __name__ == "__main__":
    main()