import fortiAPI as fapi
import pprint
pp = pprint.PrettyPrinter(indent=4)

ipAddress = ""
httpsPort = ""
loginUsername = ""
loginPassword = ""

device = fapi.FortiGate(ipaddr=ipAddress,username=loginUsername,password=loginPassword,timeout=10,vdom='root',port=httpsPort)
result = device.get_interfaces()
pp.pprint(result)