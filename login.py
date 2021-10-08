import sys
import fortiAPI as fapi
class login:
    def login(self, devices):
        sessions = {}
        for name,device in devices.items():
            ipAddress = device[0]
            httpsPort = device[1]
            loginUsername = device[2]
            loginPassword = device[3]
            sessions[name] = (fapi.FortiGate(ipaddr=ipAddress,username=loginUsername,password=loginPassword,timeout=10,vdom='root',port=httpsPort))

        return sessions
sys.modules[__name__] = login()