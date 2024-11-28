import os
import time
import math
from icmplib import multiping, is_ipv4_address, is_ipv6_address, resolve
import httpx
import git
import json
from pyroute2 import NDB, WireGuard

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
    if not os.path.exists("/etc/bird/ibgp/peers"):
        os.mkdir("/etc/bird/ibgp")
        os.mkdir("/etc/bird/ibgp/peers")
    return True

def update_assignment():
    global_config_file = open("/etc/bird/network.json")
    global_config = json.loads(global_config_file.read())
    global_config_file.close()

    priv_ipv4 = global_config["nodes"][NODE]["clearnet"]["ip"]["v4"][0]
    priv_asn = "42925" + "".join(filter(str.isdigit, priv_ipv4))[-5:]

    conf_file = "/etc/bird/auto_assign.conf"
    conf = ""

    conf += "define PRIV_AS = %s;\n"%priv_asn
    conf += "define NET_AS = %s;\n"%global_config["global"]["clearnet"]["asn"]
    conf += "\n\n"

    clearnet_ipnet = global_config["global"]["clearnet"]["routes"]["v4"] | global_config["nodes"][NODE]["clearnet"]["routes"]["v4"]
    clearnet_ipv6net = global_config["global"]["clearnet"]["routes"]["v6"] | global_config["nodes"][NODE]["clearnet"]["routes"]["v6"]

    if len(clearnet_ipnet.keys()) > 0:
        conf += "define NET_SELF_NETSET = [%s];\n"%",".join(str(x+"+") for x in clearnet_ipnet.keys())
    if len(clearnet_ipv6net.keys()) > 0:
        conf += "define NET_SELF_NETSETv6 = [%s];\n"%",".join(str(x+"+") for x in clearnet_ipv6net.keys())

    if global_config["nodes"][NODE]["clearnet"]["ip"]["v4"]:
        conf += "define NET_SELF_IP = %s;\n"%global_config["nodes"][NODE]["clearnet"]["ip"]["v4"][0]

    if global_config["nodes"][NODE]["clearnet"]["ip"]["v6"]:
        conf += "define NET_SELF_IPv6 = %s;\n"%global_config["nodes"][NODE]["clearnet"]["ip"]["v6"][0]

    conf += "\n\n"

    self_ipv4 = global_config["nodes"][NODE]["clearnet"]["ip"]["v4"] + global_config["nodes"][NODE]["clearnet"]["anycast_ip"]["v4"]
    self_ipv6 = global_config["nodes"][NODE]["clearnet"]["ip"]["v6"] + global_config["nodes"][NODE]["clearnet"]["anycast_ip"]["v6"]

    conf += "define SELF_IPv4_LIST = "
    if len(self_ipv4) > 1:
        conf += "["+", ".join(str(x+"/32") for x in self_ipv4)+"];\n"
    else:
        conf += self_ipv4[0]+"/32;\n"

    conf += "define SELF_IPv6_LIST = "
    if len(self_ipv6) > 1:
        conf += "["+", ".join(str(x+"/128") for x in self_ipv6)+"];\n"
    else:
        conf += self_ipv6[0]+"/128;\n"

    conf += "\n\n"


    if len(clearnet_ipnet.keys()) > 0:
        conf += "protocol static NET_ROUTE {\n"
        for net in clearnet_ipnet.keys():
            if not clearnet_ipnet[net]:
                conf += "  route %s reject;\n"%net
            else:
                conf += "  route %s via \"%s\";\n"%(net, clearnet_ipnet[net])
        conf += "  ipv4 {\n    import filter { bgp_large_community.add((NET_AS, 2000, NET_AS)); accept; };\n    export none;\n  };\n}\n"
    if len(clearnet_ipv6net.keys()) > 0:
        conf += "protocol static NET_ROUTEv6 {\n"
        for net in clearnet_ipv6net.keys():
            if not clearnet_ipv6net[net]:
                conf += "  route %s reject;\n"%net
            else:
                conf += "  route %s via \"%s\";\n"%(net, clearnet_ipv6net[net])
        conf += "  ipv6 {\n    import filter { bgp_large_community.add((NET_AS, 2000, NET_AS)); accept; };\n    export none;\n  };\n}\n"

    conf += "function NET_SELF_NET_CHECK() {\n  case net.type {\n"
    if len(clearnet_ipnet.keys()) > 0:
        conf += "      NET_IP4: return net ~ NET_SELF_NETSET;\n"
    else :
        conf += "      NET_IP4: return false;\n"
    if len(clearnet_ipv6net.keys()) > 0:
        conf += "      NET_IP6: return net ~ NET_SELF_NETSETv6;\n"
    else :
        conf += "      NET_IP6: return false;\n"
    conf += "  }\n}\n\n"

    #RPKI
    if "slim" not in global_config["nodes"][NODE]:
        conf += "roa4 table NET_RPKI;\nroa6 table NET_RPKIv6;\n"
        conf += "protocol rpki RPKI_CloudFlare {\n  #roa4 { table NET_RPKI; };\n  roa6 { table NET_RPKIv6; };\n  remote \"rtr.rpki.cloudflare.com\" port 8282;\n}\n"
        conf += "function RPKI_INVALID() {\n  case net.type {\n    NET_IP4: return true;#NET_IP4: return roa_check(NET_RPKI, net, bgp_path.last_nonaggregated) = ROA_INVALID;\n    NET_IP6: return roa_check(NET_RPKIv6, net, bgp_path.last_nonaggregated) = ROA_INVALID;\n  }\n}\n"
    else:
        conf += "function RPKI_INVALID() {\n  case net.type {\n    NET_IP4: return true;\n    NET_IP6: return true;\n  }\n}\n"


    f = open(conf_file, "w")
    f.write(conf)
    f.close()

    #key1 = (os.getenv("WG_A_PUBKEY"), os.getenv("WG_A_PRIVKEY"))
    #key2 = (os.getenv("WG_B_PUBKEY"), os.getenv("WG_B_PRIVKEY"))
    #global_config = build_bridge(global_config, [key1, key2])
    
    update_ibgp_peers(global_config)
    update_hosts(global_config)

    os.system("birdc c")

    return True

def build_bridge(config, keys):
    peers = config["nodes"][NODE]["direct"]
    for zone in config["nodes"][NODE]["zone"]:
        for node in config["nodes"].keys():
            if node != NODE and node not in peers:
                if zone in config["nodes"][node]["zone"]:
                    peers.append(node)

    ndb = NDB()
    interfaces = ndb.interfaces.summary()
    links = []
    for link in interfaces:
        links.append(link.ifname)

    if "LINK_DUMMY" not in links:
        (ndb
         .interfaces
         .create(ifname="LINK_DUMMY", kind='dummy')
         .commit()
        )
        for net_ipv4 in config["nodes"][NODE]["clearnet"]["ip"]["v4"] + config["nodes"][NODE]["clearnet"]["anycast_ip"]["v4"]:
            (ndb
             .interfaces["LINK_DUMMY"]
             .add_ip(net_ipv4+"/32")
             .commit()
            )
        for net_ipv6 in config["nodes"][NODE]["clearnet"]["ip"]["v6"] + config["nodes"][NODE]["clearnet"]["anycast_ip"]["v6"]:
            (ndb
             .interfaces["LINK_DUMMY"]
             .add_ip(net_ipv6+"/128")
             .commit()
            )
        (ndb
        .interfaces["LINK_DUMMY"]
        .set("state", "up")
        .commit()
        )

    for peer in peers:
        link_name = "LINK_"
        pos = 0
        if NODE[0:2] == peer[0:2]:
            #Same Location
            if len(NODE) < len(peer) or (len(NODE) == len(peer) == 4 and int(NODE[3]) < int(peer[3])):
                #Should be XXX - XXX2 / XXX2-XXX3
                pos = 0
                link_name += NODE.upper()+"_"+peer.upper()
            else:
                #Should be XXX2 - XXX
                pos = 1
                link_name += peer.upper()+"_"+NODE.upper()
        else:
            if NODE[0] == peer[0]:
              #Two Loc Code First Char same
              if NODE[1] < peer[1]:
                pos = 0
                link_name += NODE.upper()+"_"+peer.upper()
              else:
                pos = 1
                link_name += peer.upper()+"_"+NODE.upper()  
            elif NODE[0] < peer[0]:
                pos = 0
                link_name += NODE.upper()+"_"+peer.upper()
            else:
                pos = 1
                link_name += peer.upper()+"_"+NODE.upper()
        config["nodes"][peer]["pos"] = pos
        config["nodes"][peer]["link_name"] = link_name

        if link_name not in links:
            wg = WireGuard()
            (ndb
             .interfaces
             .create(ifname=link_name, kind='wireguard')
             .commit()
            )
            print(link_name + " Link Created")
            try:
                peer_connect_point = resolve(peer+".yuetau.net")[0]
            except:
                peer_connect_point = "127.0.0.1"
            print(link_name + " Resolved to " + peer_connect_point)
            wg_peer = {
                "public_key": keys[int(not pos)][0],
                "endpoint_addr": peer_connect_point,
                "endpoint_port": int(config["nodes"][NODE]["clearnet"]["ip"]["v4"][0].split(".")[-1])+10000,
                "persistent_keepalive": 300,
                "allowed_ips": ['0.0.0.0/0', '::/0']
            }
            wg.set(link_name, private_key=keys[pos][1], listen_port=int(config["nodes"][peer]["clearnet"]["ip"]["v4"][0].split(".")[-1])+10000, peer=wg_peer)
            print(link_name + " WG Configured")
            (ndb
            .interfaces[link_name]
            .set("state", "up")
            .commit()
            )
            print(link_name + " Link Set Up")

            link_index = ndb.interfaces[link_name]["index"]
            for net_ipv4 in config["nodes"][NODE]["clearnet"]["ip"]["v4"]:
                try:
                    (ndb
                     .interfaces[link_name]
                     .add_ip(net_ipv4+"/32")
                     .commit()
                    )
                except:
                    print(link_name + " unable create IPv4 " + net_ipv4)
                for peer_net_ipv4 in config["nodes"][peer]["clearnet"]["ip"]["v4"]:
                    if net_ipv4 == peer_net_ipv4:
                        pass
                    try:
                        (ndb
                         .routes
                         .create(dst=peer_net_ipv4+"/32", oif=link_index)
                         .commit()
                        )
                    except:
                        print(link_name + " unable create IPv4 route " + net_ipv4)
            print(link_name + " IPv4 Complete")
            try:
                (ndb
                 .interfaces[link_name]
                 .add_ip("fe80::925:"+str(pos)+"/64")
                 .commit()
                )
            except:
                print(link_name + " unable create IPv6 " + "fe80::925:"+str(pos)+"/64")
            print(link_name + " IPv6 Complete")
    ndb.close()
    return config
    

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
        ipv6 = "fe80::0925:"+str(int(not global_config["nodes"][peer]["pos"]))+"%"+global_config["nodes"][peer]["link_name"]
        peer_file = peer_folder+peer+".conf"
        peer_conf = ""

        if "slim" not in global_config["nodes"][peer]:
            peer_conf += "protocol bgp IBGP_%s from IBGP_PEER {\n"%peer.upper()
        else:
            peer_conf += "protocol bgp IBGP_%s from IBGP_DEFROUTE_PEER {\n"%peer.upper()
        peer_conf += "    neighbor %s external;\n"%ipv6
        peer_conf += "}"

        f = open(peer_file, "w")
        f.write(peer_conf)
        f.close()

def update_hosts(config):
    hosts = """
    127.0.0.1       localhost

    # The following lines are desirable for IPv6 capable hosts
    ::1     localhost ip6-localhost ip6-loopback
    ff02::1 ip6-allnodes
    ff02::2 ip6-allrouters


    """


    for c_node in config["nodes"].keys():
        if c_node == NODE:
            hosts += "\n%s %s"%("127.0.0.1", c_node+".YuetAuNet")
            hosts += "\n%s %s"%("::1", c_node+".YuetAuNet")
        for ipv4 in config["nodes"][c_node]["clearnet"]["ip"]["v4"]:
            hosts += "\n%s %s"%(ipv4, c_node+".YuetAuNet")
        for ipv6 in config["nodes"][c_node]["clearnet"]["ip"]["v6"]:
            hosts += "\n%s %s"%(ipv6, c_node+".YuetAuNet")

    hosts_file = open("/etc/hosts", "w")
    hosts_file.write(hosts)


update_configs()
update_assignment()
#update_metrics()
