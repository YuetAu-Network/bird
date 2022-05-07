import os
import json
import subprocess

bgp_path = "/etc/bird/dn42/peers/auto/"
bgp_dir_list = os.listdir(bgp_path)

wg_path = "/etc/wireguard/auto/"

config = []
wg_privkeyfile = open("/etc/wireguard/privatekey")
config.append({"key": wg_privkeyfile.read()})

for bgp_filename in bgp_dir_list:
    conn_name = bgp_filename.split(".")[0]
    if os.path.exists(wg_path+bgp_filename):
        obj = {}
        bgp_file = open(bgp_path+bgp_filename)
        wg_file = open(wg_path+bgp_filename)

        addrs = []
        addr_count = 0
        obj["mp"] = True
        for line in bgp_file:
            if "neighbor" in line:
                tmp = line.split(" ")
                peer_addr = tmp[3]
                asn = tmp[5][:-2]
                addr_count = addr_count + 1
                addrs.append((peer_addr, asn))
            elif "password" in line:
                if "special" not in obj:
                    obj["special"] = {}
                obj["special"]["password"] = line.split(" ")[3]
            elif "source address" in line:
                if "special" not in obj:
                    obj["special"] = {}
                obj["special"]["source_addr"] = line.split(" ")[3]
        if addr_count > 1:
            obj["mp"] = False
        obj["addrs"] = addrs

        for line in wg_file:
            if "ListenPort" in line:
                obj["port"] = int(line.split("=")[1][1:-1])
            elif "PublicKey" in line:
                obj["pubkey"] = line.split("=")[1][1:]+"="
            elif "Endpoint" in line:
                obj["endpoint"] = line.split("=")[1][1:-1]

        bgp_file.close()
        wg_file.close()

        child = subprocess.Popen(['ip','a','show',conn_name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = child.stdout.read().decode("utf-8")
        for line in output.split("\n"):
            if "inet6" in line:
                tmp = line.split(" ")
                obj["src_ipv6"] = tmp[5]
            elif "inet" in line:
                tmp = line.split(" ")
                obj["src_ip"] = tmp[5]
                if tmp[6] == "peer":
                    obj["peer_ip"] = tmp[7]


        config.append(obj)

print(json.dumps(config))
