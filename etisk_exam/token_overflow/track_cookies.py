import requests

session = requests.Session()

print("Request 1: Homepage")
r1 = session.get("http://challenges.iik3100-h25.iaas.iik.ntnu.no:11080/")
print(f"Cookies after homepage: {session.cookies.get_dict()}")
print(f"Set-Cookie headers: {r1.headers.get('Set-Cookie', 'None')}")
print()

print("Request 2: Profile")
r2 = session.get("http://challenges.iik3100-h25.iaas.iik.ntnu.no:11080/profile")
print(f"Cookies after profile: {session.cookies.get_dict()}")
print(f"Set-Cookie headers: {r2.headers.get('Set-Cookie', 'None')}")
print()

print("Request 3: Admin (will fail)")
r3 = session.get("http://challenges.iik3100-h25.iaas.iik.ntnu.no:11080/admin")
print(f"Status: {r3.status_code}")
print(f"Cookies after admin attempt: {session.cookies.get_dict()}")
print(f"Set-Cookie headers: {r3.headers.get('Set-Cookie', 'None')}")
