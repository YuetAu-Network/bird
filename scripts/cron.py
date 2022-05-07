import os
import time
import math
from icmplib import multiping, is_ipv4_address, is_ipv6_address, resolve
import httpx
import git
import json
from pyroute2 import NDB, WireGuard
import ipaddress

CHECKIN_URL = "https://netstat.yuetau.net/node/checkin"
NODE = os.uname()[1].split(".")[0]

def update_metrics():
    path = "/etc/bird/mixed/"
    files = os.listdir(path)

    host = {}
    ips = []
    for f in files:
        nodeid = f.split(".")[0].split("_")[1]
        f = open(path+f, "r").read()
        ip = re.search(IPV6_REGEX, f).group()
        host[ip.split(":")[4]] = {}
        host[ip.split(":")[4]]["nodeid"] = nodeid
        host[ip.split(":")[4]]["ip"] = ip
        ips.append(host[ip.split(":")[4]]["ip"])

    mp = multiping(ips, count=6)
    for h in mp:
            host[h.address.split(":")[4]]["rtt"] = math.ceil(h.avg_rtt)

    conf_file = "/etc/bird/clearnet/auto_med.conf"
    conf = ""
    obj = {}
    for h in host.keys():
        obj[host[h]["nodeid"]] = host[h]["rtt"]
        if host[h]["rtt"] > 0:
            conf += "      %s: bgp_med = bgp_med + %s;\n"%(str(h), str(host[h]["rtt"]))
        else:
            conf += "      %s: bgp_med = bgp_med + 10000;\n"%str(h)
    f = open(conf_file, "w")
    f.write("#Generated at %s\nfunction IBGP_MED_EXPORT(int node) {\n    case node {\n%s      else: reject;\n    }\n}\n"%(time.strftime('%x, %X %Z'), conf))
    f.close()

    hb = {}
    hb["node"] = NODE
    hb["mts"] = obj
    res = httpx.post(CHECKIN_URL, json=hb)

    return True

def update_configs():
    repo = git.Repo("/etc/bird/")
    repo.remotes.origin.pull()
    if os.stat("/etc/bird/network.json").st_mtime > (time.time() - 60):
        update_assignment()
    if not os.path.exists("/etc/bird.conf"):
        os.symlink("/etc/bird/bird.conf", "/etc/bird.conf")
    if not os.path.exists("/etc/bird/clearnet/peers"):
        os.mkdir("/etc/bird/clearnet")
        os.mkdir("/etc/bird/clearnet/peers")
    if not os.path.exists("/etc/bird/dn42/peers"):
        os.mkdir("/etc/bird/dn42/peers")
    if not os.path.exists("/etc/bird/ibgp/peers"):
        os.mkdir("/etc/bird/ibgp")
        os.mkdir("/etc/bird/ibgp/peers")
    return True

def update_assignment():
    global_config_file = open("/etc/bird/network.json")
    global_config = json.loads(global_config_file.read())
    global_config_file.close()

    ndb = NDB()

    priv_ipv4 = global_config["nodes"][NODE]["clearnet"]["ip"]["v4"][0]
    priv_asn = "42925" + "".join(filter(str.isdigit, priv_ipv4))[-5:]

    if ndb.interfaces.dump().filter(ifname="dummy0").count() == 0:
        (ndb
         .interfaces
         .create(ifname="dummy0", kind="dummy")
         .set("state", "up")
         .commit())
    elif ndb.interfaces["dummy0"].ipaddr.dump().count() > 0:
        (ndb
         .interfaces["dummy0"]
         .del_ip()
         .commit())

    conf_file = "/etc/bird/auto_assign.conf"
    conf = ""

    conf += "define PRIV_AS = %s;\n"%priv_asn
    conf += "define NET_AS = %s;\n"%global_config["global"]["clearnet"]["asn"]
    conf += "define DN42_AS = %s;\n"%global_config["global"]["dn42"]["asn"]
    conf += "\n\n"

    clearnet_ipnet = global_config["global"]["clearnet"]["routes"]["v4"] | global_config["nodes"][NODE]["clearnet"]["routes"]["v4"]
    clearnet_ipv6net = global_config["global"]["clearnet"]["routes"]["v6"] | global_config["nodes"][NODE]["clearnet"]["routes"]["v6"]

    if len(clearnet_ipnet.keys()) > 0:
        conf += "define NET_SELF_NETSET = [%s];\n"%",".join(str(x+"+") for x in clearnet_ipnet.keys())
    if len(clearnet_ipv6net.keys()) > 0:
        conf += "define NET_SELF_NETSETv6 = [%s];\n"%",".join(str(x+"+") for x in clearnet_ipv6net.keys())

    clearnet_ipv4_flag = False
    clearnet_ipv6_flag = False
    for ip in global_config["nodes"][NODE]["clearnet"]["ip"]["v4"]:
        #ndb.interfaces["dummy0"].add_ip(ip+"/32").commit()
        if not clearnet_ipv4_flag:
            conf += "define NET_SELF_IP = %s;\n"%ip
            clearnet_ipv4_flag = True
            continue

    for ip in global_config["nodes"][NODE]["clearnet"]["ip"]["v6"]:
        #ndb.interfaces["dummy0"].add_ip(ip+"/128").commit()
        if not clearnet_ipv6_flag:
            conf += "define NET_SELF_IPv6 = %s;\n"%ip
            clearnet_ipv6_flag = True
            continue

    conf += "\n\n"


    dn42_ipnet = global_config["global"]["dn42"]["routes"]["v4"] | global_config["nodes"][NODE]["dn42"]["routes"]["v4"]
    dn42_ipv6net = global_config["global"]["dn42"]["routes"]["v6"] | global_config["nodes"][NODE]["dn42"]["routes"]["v6"]

    if len(dn42_ipnet.keys()) > 0:
        conf += "define DN42_SELF_NETSET = [%s];\n"%",".join(str(x+"+") for x in dn42_ipnet.keys())
    if len(dn42_ipv6net.keys()) > 0:
        conf += "define DN42_SELF_NETSETv6 = [%s];\n"%",".join(str(x+"+") for x in dn42_ipv6net.keys())

    dn42_ipv4_flag = False
    dn42_ipv6_flag = False
    for ip in global_config["nodes"][NODE]["dn42"]["ip"]["v4"]:
        ndb.interfaces["dummy0"].add_ip(ip+"/32").commit()
        if not dn42_ipv4_flag:
            conf += "define DN42_SELF_IP = %s;\n"%ip
            dn42_ipv4_flag = True
            continue

    for ip in global_config["nodes"][NODE]["dn42"]["ip"]["v6"]:
        ndb.interfaces["dummy0"].add_ip(ip+"/128").commit()
        if not dn42_ipv6_flag:
            conf += "define DN42_SELF_IPv6 = %s;\n"%ip
            dn42_ipv6_flag = True
            continue

    conf += "\n\n"


    if len(clearnet_ipnet.keys()) > 0:
        conf += "protocol static NET_ROUTE {\n"
        for net in clearnet_ipnet.keys():
            if not clearnet_ipnet[net]:
                conf += "  route %s reject;\n"%net
            else:
                conf += "  route %s via \"%s\";\n"%(net, clearnet_ipnet[net])
        conf += "  ipv4 {\n    import filter { bgp_large_community.add((NET_AS, 300, NET_AS)); accept; };\n    export none;\n  };\n}\n"
    if len(clearnet_ipv6net.keys()) > 0:
        conf += "protocol static NET_ROUTEv6 {\n"
        for net in clearnet_ipv6net.keys():
            if not clearnet_ipv6net[net]:
                conf += "  route %s reject;\n"%net
            else:
                conf += "  route %s via \"%s\";\n"%(net, clearnet_ipv6net[net])
        conf += "  ipv6 {\n    import filter { bgp_large_community.add((NET_AS, 300, NET_AS)); accept; };\n    export none;\n  };\n}\n"

    if len(dn42_ipnet.keys()) > 0:
        conf += "protocol static DN42_ROUTE {\n"
        for net in dn42_ipnet.keys():
            if not dn42_ipnet[net]:
                conf += "  route %s reject;\n"%net
            else:
                conf += "  route %s via \"%s\";\n"%(net, dn42_ipnet[net])
        conf += "  ipv4 {\n    import all;\n    export none;\n  };\n}\n"
    if len(dn42_ipv6net.keys()) > 0:
        conf += "protocol static DN42_ROUTEv6 {\n"
        for net in dn42_ipv6net.keys():
            if not dn42_ipv6net[net]:
                conf += "  route %s reject;\n"%net
            else:
                conf += "  route %s via \"%s\";\n"%(net, dn42_ipv6net[net])
        conf += "  ipv6 {\n    import all;\n    export none;\n  };\n}\n"

    conf += "function NET_SELF_NET_CHECK() {\n  case net.type {\n"
    if len(clearnet_ipnet.keys()) > 0:
        conf += "      NET_IP4: return net ~ NET_SELF_NETSET;\n"
    else :
        conf += "      NET_IP4: return false;\n"
    if len(clearnet_ipv6net.keys()) > 0:
        conf += "      NET_IP6: return net ~ NET_SELF_NETSETv6;\n"
    else :
        conf += "      NET_IP6: return false;\n"
    conf += "  }\n}\n"

    conf += "function DN42_SELF_NET_CHECK() {\n  case net.type {\n"
    if len(dn42_ipnet.keys()) > 0:
        conf += "      NET_IP4: return net ~ DN42_SELF_NETSET;\n"
    else :
        conf += "      NET_IP4: return false;\n"
    if len(dn42_ipnet.keys()) > 0:
        conf += "      NET_IP6: return net ~ DN42_SELF_NETSETv6;\n"
    else :
        conf += "      NET_IP6: return false;\n"
    conf += "  }\n}\n"

    f = open(conf_file, "w")
    f.write(conf)
    f.close()

    ndb.close()

    update_ibgp_peers(global_config)

    os.system("birdc c")

    return True

def update_ibgp_peers(global_config):
    peer_folder = "/etc/bird/ibgp/peers/"

    for file_name in os.listdir(peer_folder):
        if file_name.endswith('.conf'):
            os.remove(peer_folder + file_name)

    peers = []
    for tzone in global_config["nodes"][NODE]["zone"]:
        for tnode in global_config["nodes"]:
            if tnode != NODE and tzone in global_config["nodes"][tnode]["zone"]:
                peers.append(tnode)
    peers = peers + global_config["nodes"][NODE]["direct"]

    for peer in peers:
        ipv6 = global_config["nodes"][peer]["clearnet"]["ip"]["v6"][0]
        peer_file = peer_folder+peer+".conf"
        peer_conf = ""

        peer_conf += "protocol bgp IBGP_%s from IBGP_PEER {\n"%peer.upper()
        peer_conf += "    neighbor %s external;\n"%ipv6
        peer_conf += "}"

        f = open(peer_file, "w")
        f.write(peer_conf)
        f.close()

def update_wg_allowedips():
    wg = WireGuard()

    IFNAME = "nm-YuetAuNet"

    peer_info = wg.info(IFNAME)[0]["attrs"][6][1]

    pubkey_list = []
    for peer in peer_info:
        pubkey_list.append(peer["attrs"][0][1].decode('UTF-8'))

    for pubkey in pubkey_list:
        os.popen("wg set %s peer %s allowed-ips 0.0.0.0/0,::/0"%(IFNAME, pubkey))



update_configs()
update_assignment()
update_wg_allowedips()
#update_metrics();
