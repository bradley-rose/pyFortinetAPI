import sys
import fortiAPI as fapi
class login:
    def login(self, devices):
        sessions = {}
        for name,device in devices.items():
            sessions[name] = (fapi.FortiGate(
                ipaddr=device['ipaddr'],
                username=device['username'],
                password=device['password'],
                port=device['port'],
                networkAddressCIDR=device['networkAddressCIDR'],
                role=device['role'],
                region=device['region']
                )
            )

        return sessions
sys.modules[__name__] = login()