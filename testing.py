import fortiAPI as fapi
import pprint

def login(devices):

    sessions = {}
    for name,device in devices.items():
        ipAddress = device[0]
        httpsPort = device[1]
        loginUsername = device[2]
        loginPassword = device[3]
        sessions[name] = (fapi.FortiGate(ipaddr=ipAddress,username=loginUsername,password=loginPassword,timeout=10,vdom='root',port=httpsPort))

    return sessions

def main():
    # Load a local variable for PP
    pp = pprint.PrettyPrinter(indent=4)

    # Login to each device
    devices = {}
    devices["DeviceA"] = ["IP Address","Port","LoginUsername","Password"]
    devices["DeviceB"] = ["IP Address","Port","LoginUsername","Password"]

    sessions = login(devices)

    # Perform operations
    for name,device in sessions.items():
        print("Device Name:",name)

        # Get System Status
        status = device.get_system_status()
        print("Version:",status["version"])

        # Get Interfaces
        #interfaces = device.get_interfaces()
        #for interface in interfaces:
            #print("Interface Name:",interface["name"])
            #print("Alias:", interface["alias"])
            #print("Members:", interface["member"])

        print("------******------")
        

if __name__ == "__main__":
    main()