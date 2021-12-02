datalink_proto = {"Ethernet": 14 }
datalink_type = {
    "0800": "DoD Internet (IP Datagram)",
    "0805": "X.25 level 3",
    "0806": "ARP",
    "8035": "RARP",
    "8098": "Appletalk",
    }

def trim_datalink(hex_list, protocol = "Ethernet"):
    index = datalink_proto[protocol]
    header = hex_list[:index+1]
    data = hex_list[index:]

    return header, data

