import socket
import sys
import json

# Check if argvLen is correct
if len(sys.argv) != 2:
    print("Invalid argument length")
    exit()

# Read the command line arguments for port and IP
scanIP = sys.argv[1]

with open("commonPorts.json", 'r') as file:
    data = json.load(file)

# Create an array of ports to scan
ports = []

for i in data["ports"]:
    ports.append(i["port"])

print("Scanning common ports on %s" %(scanIP))

# Loop through first 1000 ports
for port in ports:
    try:
        s = socket.socket()        
        s.settimeout(0.1)
        s.connect((scanIP, port))
        print("Port %s is open" %(port))
        s.close() 
    except:
        pass
