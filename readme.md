# Fortigate REST API
This is a base Python wrapper for the FortiOS API. Create custom logic as necessary, including creating new CRUD actions in `apiWrapper.py`. Of note, this doesn't include any amount of inventory management. Integrate your source of truth for inventory management as you see fit.

To use `apiWrapper.py`:

```py
import apiWrapper as fgApi

def actionsToPerform(*, api: dict):
    with api.FortiGate(**{
        "hostAddress": "<IP address of FortiGate management interface>",
        "port": "<HTTPS port where web interface is accessible>",
        # If authenticating via apiKey:
        "apiKey": "<apiKey>".
        # Or, if authenticating via username/password:
        "username": "<username>",
        "password": "<password>"
    }) as fortiGate:
        # Syntax: result = fortiGate.<functionFrom_apiWrapper.py>
        # Example:
        result = fortiGate.getUserGroup(name="<groupName>")
        return result

def main():
    resultFromApiCall = actionsToPerform(api = fgApi)

if __name__ == "__main__":
    main()
```
