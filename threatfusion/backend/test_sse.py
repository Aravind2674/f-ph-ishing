import urllib.request, json
req = urllib.request.Request("http://127.0.0.1:8001/network/stream-ticket", data=b"{}", method="POST")
req.add_header("Content-Type", "application/json")
with urllib.request.urlopen(req) as res:
    ticket = json.loads(res.read().decode())["ticket"]
print("Ticket:", ticket)
req2 = urllib.request.Request("http://127.0.0.1:8001/network/packets?ticket=" + ticket)
with urllib.request.urlopen(req2) as res:
    print("Connected!")
    for line in res:
        print(line.decode().strip())

