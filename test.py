import requests

url = "https://10.69.10.25:8443/api/v2/cmdb/system/status"

payload={}
headers = {'Cookie': 'APSCOOKIE_1121005630="Era%3D0%26Payload%3DP7H+s2h8QmjokYe7p4sS18tliv6FGD4iYaCPAGWy5Eedvz8Rpkk4TdrhCr9cEM9L%0AvZRfGjimZFQXhuK9eO+6VZJq+DwCtbVZhypV%2FjXN6EYWuToykFkgzZHJEApHPSIu%0ABkXPRacy2dvpJ25Zj6dtPvtQDvodI85o7Req2CzaoB5j42CGN3VN7utOrri4wafl%0AYGPUv3JFSIqNLULYTvK0ZSzvDaraInB1fCma79GaDKQzIVj5BX9Xt%2Fmf%2FitKD2yK%0AjtwSpGeNfpPPHK2EFnUcov4WnGjLTJ+9Ug%2FQhC9gb+4ZxR3zKvAb8Tz1MuFtopsn%0A+Jth24advJPtcwjkT5H8UQ%3D%3D%0A%26AuthHash%3DFQeB%2FKn5Qih0ANwMb2jPy1mu6jkA%0A"; ccsrftoken="7EB5C5AE2C1ED4415D58E834829FDFF7"; ccsrftoken_1121005630="7EB5C5AE2C1ED4415D58E834829FDFF7"'
}

response = requests.request("GET", url, headers=headers, data=payload, verify=False)


print(response.text)