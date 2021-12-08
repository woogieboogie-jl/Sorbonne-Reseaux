dhcp_op_dict = { 1: "DNS Request Client", 2: "DHCP Reply Server"}
dhcp_htype_dict = {
    1: "Ethernet",
    6: "IEEE 802 Networks",
    7: "ARCNET",
    12: "LocalTalk",
    14: "LocalNet",
    15: "SMDS",
    16: "Frame Relay",
    17: "HDLC",
    18: "Fibre Channel",
    19: "Asynchronus Transfer Node(ATM)",
    20: "Serial Line",
}
dhcp_opt_dict = { 255: "End of Options List (EOOL)", 53: "DHCP Message"}
dhcp_msg_dict = {
    1:     "DHCPDISCOVER",
    2:     "DHCPOFFER",
    3:     "DHCPREQUEST",
    4:     "DHCPDECLINE",
    5:     "DHCPACK",
    6:     "DHCPNAK",
    7:     "DHCPRELEASE",
    }

def getOPCode(octets):
    op = int(octets[0],16)
    return f"Operation Code: {op}({dhcp_op_dict.get(op, 'Unknown')})", op

def getHtype(octets):
    htype = int(octets[1], 16)
    return f"Hardware Address Type: {htype}({dhcp_htype_dict.get(htype, 'Unknown')})", htype

def getHLength(octets):
    hlen = int(octets[2],16)*8
    return f"Length: {hlen} octets"

def getHops(octets):
    return f"Hops: {int(octets[3],16)}"

def getCIID(octets):
    return f"Client ID: {int(octets[4]+octets[5]+octets[6]+octets[7],16)}"

def getSTime(octets):
    ST = int(octets[8]+octets[9],16)
    return f"Start Time: {ST}"

def getFlags(octets):
    flags = octets[10]+octets[11]
    return f"Flags: {flags}"

def getCIAddr(octets):
    ciaddr = '.'.join([str(int(octet, 16)) for octet in octets[12:16]])
    return f"Client Address: {ciaddr}"

def getYIAddr(octets):
    yiaddr = '.'.join([str(int(octet, 16)) for octet in octets[16:20]])
    return f"Offered Address: {yiaddr}"

def getSIAddr(octets):
    siaddr = '.'.join([str(int(octet, 16)) for octet in octets[20:24]])
    return f"Server Address: {siaddr}"

def getGIAddr(octets):
    giaddr = '.'.join([str(int(octet, 16)) for octet in octets[24:28]])
    return f"Relay Agent Address: {giaddr}"

def getCHAddr(octets, htype):
    if htype == 1:
        chaddr = '.'.join(octets[28:34])
        return f"Client Hardware Address: {chaddr}({dhcp_htype_dict.get(htype)})"
    else:
        chaddr = '-'.join(octets[28:44])
        return f"Client Hardware Address: {chaddr}({dhcp_htype_dict.get(htype)})"

def getOptSName(octets):
    sname_data = ''.join(octets[44:108])
    if int(sname_data,16) == 0:
        return f"Server Host Name: None (Not Given)"
    else:
        sname = (sname_data).decode("hex")
        return f"Server Host Name: {sname}"

def getOptFName(octets):
    bname_data = ''.join(octets[108:236])
    if int(bname_data,16) == 0:
        return f"Boot File Name: None (Not Given)"
    else:
        bname = (bname_data).decode("hex")
        return f"Boot File Name: {bname}"

def getOptions(octets):
    opts_out = ["Options"]
    if octets[236:240] == ["63", "82", "53", "63"]:
        opt_list = octets[240:]
    else:
        opt_list = octets[236:]
    if len(opt_list) == 0:
        opts_out.append("No options avaliable")
    else:
        while len(opt_list) > 0:
            o = int(opt_list[0], 16)
            opt = dhcp_opt_dict.get(o, "Unknown Option")
            opts_out.append(f"\t{o}: {opt}")
            if o == 255:
                break
            else:
                print(opt_list[0])
                print(opt_list[1])
                print(opt_list[2])
                opt_len = int(opt_list[1], 16)
                opts_out.append(f"\t\tOption Length: {opt_len} bytes")
                opt_val_hex = ''.join(opt_list[2:2+opt_len])
                opt_val_dec = int(opt_val_hex, 16)
                if o==53:
                    opts_out.append(f"\t\tDHCP Message: {dhcp_msg_dict[opt_val_dec]} ({opt_val_hex})")
                else:    
                    opts_out.append(f"\t\tOption Value: {opt_val_dec} ({opt_val_hex})")
                opt_list = opt_list[2+opt_len:]
    return "\n".join(opts_out), opt_list




def DHCP(octets):
    OP_s, OP = getOPCode(octets)
    htype_s, htype = getHtype(octets)
    opt_s, opt_list = getOptions(octets)
    elements = [
        OP_s,
        htype_s,
        getHLength(octets),
        getHops(octets),
        getCIID(octets),
        getSTime(octets),
        getFlags(octets),
        getCIAddr(octets),
        getYIAddr(octets),
        getSIAddr(octets),
        getGIAddr(octets),
        getCHAddr(octets, htype),
        getOptSName(octets),
        getOptFName(octets),
        opt_s,
    ]
    parsed_dict = {"analysis": "\n".join(elements)}
    seg_left = opt_list
    if len(seg_left) != 0:
        parsed_dict["left"] = seg_left
        parsed_dict["analysis"] + f"\n\n ! {len(seg_left)} BYTES OF UNPACKED DATA REMAINING"
    
    return parsed_dict








# ---------------------------------------------------------------------------------------------------------------------------------------

#sources to find format and values:
    #http://www-inf.int-evry.fr/~hennequi/CoursDNS/NOTES-COURS_eng/msg.html
    #https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
    #https://spathis.medium.com/comprendre-internet-et-son-fonctionnement-9b2f63a07430
    #https://en.wikipedia.org/wiki/Domain_Name_System#DNS_message_format

#only use if DNS = True
type_rr_dict = {1: 'A', 28: 'AAAA', 5: 'CNAME', 2: 'NS', 15: 'MX'}


def Identification(octets):
    #Identification
    I = hex(int(octets[0]+octets[1],16))
    return f"Transaction ID: {I}"
    
def Control(octets):
    opcode_dic = {0: 'Query', 1: 'Inverse Query', 2:'Status', 3:'Unassigned', 4:'Notify', 5:'Update', 6:'DNS Stateful Operations'}
    rcode_dic = {0:'NOERROR', 1:'FORMERR', 2:'SERVFAIL', 3:'NXDOMAIN', 4:'NOTIMP', 5:'REFUSED', 6:'YXDOMAIN', 7:'XRRSET', 8:'NOTAUTH', 9:'NOTZONE' }
    #Control
    C = format(int(octets[2]+octets[3],16), '016b')
    QR = "Request" if C[0] == "0" else "Response"                                               # Query
    opcode = opcode_dic.get(int(C[1:5],2), "Unknown")                                           # Opcode
    AA = "Cache" if C[5] == "0" else "Authoritative"                                            # Authoritative 
    TC = "Not truncated" if C[6] == "0" else "Response too large for UDP"                       # Trancated
    RD = "Iterative" if C[7] == "0" else "Recursive"                                            # Recursion Desired
    RA = "Server does not manage recursive" if C[8] == "0" else "Server manages recursive"      # Recursion Avaliable
    Z = "Reserved for extensions" if C[9] == "0" else "Not reserved for extensions"             # Zero reserved for extensions
    Z_AD = "Not authenticated" if C[10] == "0" else "Authenticated"                             # Authenticated Data
    Z_CD = "Unacceptable" if C[11] == "0" else "Acceptable"                                     # Checking Disabled
    rcode = rcode_dic.get(int(C[12:],2), "Unknown")                                             # Reply Code
    
    return f"""
Control:
    Message: {QR}
    Opcode: {opcode} (0b{C[1:5]})
    Authoritative: {AA}
    Truncated: {TC}
    Recursion Desired: {RD}
    Recursion Avaliable: {RA}
    Z: {Z}
`   Authenticated Data: {Z_AD}
    Checking Disabled: {Z_CD}
    Reply Code: {rcode}
"""
         
def QuestionC(octets):   
    #Question count
    QC = int(octets[4] + octets[5],16)
    return f"Number of Questions: {QC}"

def AnswerC(octets):
    #Answer count
    AC = int(octets[6]+octets[7],16)
    return f"Number of Answers: {AC}"
    
def AuthorityC(octets):
    #Authority count
    AUC = int(octets[8]+octets[9],16)
    return f"Number of Authority Resource Records: {AUC}"
    
def AdditionalC(octets):
    #Additional count
    ADC = int(octets[10]+octets[11],16)
    return f"Number of Additional RRs: {ADC}"
    
def Questions(octets):
    octets = octets[12:]
    idx = octets.index("00")
    q_name_octets = octets[:idx]
    q_type_val = int("".join(octets[idx+1:idx+3]), 16)
    q_class_val = int("".join(octets[idx+3:]), 16)
    octets_out = octets[idx+5:]
    
    q_name_list = []
    for octet in q_name_octets:
        if octet[0] == '0':
            if len(q_name_list) == 0:
                pass
            else:
                q_name_list.append(".")
        else:
            q_name_list.append(chr(int(octet,16)))
                
    q_name = "".join(q_name_list)
    q_type = type_rr_dict.get(q_type_val, 'Unknown')
    q_class = hex(q_class_val)
    return f"Questions: \n\t Name: {q_name} \n\t Type: {q_type} \n\t Class: {q_class}", octets_out
    #it has to returned the chopped list without the questions as well so its easy to implement again the loop
    #for the name :)
    
def Answers(octets):
    if len(octets) == 0:
        pass
    else:
        i = 0
        Q = ''
        while octets[i] != '00': 
            Q += octets[i]
            i = i + 1
        Q = hex(int(Q,16))
        T = int("".join(octets[i:i+2]),16)
        T = type_rr_dict.get(T, 'Unknown')
        C = int("".join(octets[i+2:i+4]),16)
        C = hex(C)
        TTL = int("".join(octets[i+4:i+8]),16)
        Rdata_length = int("".join(octets[i+8:i+10]),16)
        Rdata = hex(int("".join(octets[i+10:i+10+Rdata_length]),16))
        octets = octets[i+10+Rdata_length:]
        return f"Answers: \n\t Nom de domaine: {Q} \n\t Type d'enregistrement: {T} \n\t Class: {C} \n\t TTL: {TTL} \
                \n\t Length Data: {Rdata_length} \n\t Data: {Rdata}", octets

def Authority(octets):
    if len(octets) == 0:
        return octets
    else:
        i = 0
        Q = ''
        while octets[i] != '00': 
            Q += octets[i]
            i = i + 1
        Q = hex(int(Q,16))
        T = octets[i:i+2]
        T = type_rr_dict.get(T, 'Unknown')
        C = int(octets[i+2:i+4],16)
        C = hex(C)
        TTL = int(octets[i+4:i+8],16)
        Rdata_length = int(octets[i+8,i+10],16)
        Rdata = hex(int(octets[i+10:i+10+Rdata_length],16))
        octets = octets[i+10+Rdata_length:]
        return f"Authority: \n\t Nom de domaine: {Q} \n\t Type d'enregistrement: {T} \n\t Class: {C} \n\t TTL: {TTL} \
                \n\t Length Data: {Rdata_length} \n\t Data: {Rdata}", octets   
    
def Additional(octets):
    if len(octets) == 0:
        return "", octets
    else:
        i = 0
        Q = ''
        while octets[i] != '00': 
            Q += octets[i]
            i = i + 1
        Q = hex(int(Q,16))
        T = octets[i:i+2]
        T = type_rr_dict.get(T, 'Unknown')
        C = int(octets[i+2:i+4],16)
        C = hex(C)
        TTL = int(octets[i+4:i+8],16)
        Rdata_length = int(octets[i+8,i+10],16)
        Rdata = hex(int(octets[i+10:i+10+Rdata_length],16))
        octets = octets[i+10+Rdata_length:]
        return f"Additional: \n\t Nom de domaine: {Q} \n\t Type d'enregistrement: {T} \n\t Class: {C} \n\t TTL: {TTL} \
                \n\t Length Data: {Rdata_length} \n\t Data: {Rdata}", octets

            
    
def DNS(octets):
    
    elements = [
        Identification(octets),             # Identification
        Control(octets),                    # Control
        QuestionC(octets),                  # Questions Count
        AnswerC(octets),                    # Answers Count
        AuthorityC(octets),                 # Authority Count
        AdditionalC(octets),                # Additional Count
    ]

    #Questions
    que_s, octets = Questions(octets)
    elements.append(que_s)
    if len(octets) != 0:
        #Answers
        ans_s, octets = Answers(octets)
        elements.append(ans_s)
        print(ans_s)
        print(octets)
        if len(octets) != 0:
            #Authority
            aut_s, octets = Authority(octets)
            elements.append(aut_s)
            if len(octets) != 0:
                #Additional
                add_s, seg_left = Additional(octets)
                elements.append(add_s)

    parsed_dict = {"analysis": "\n".join(elements)}
    try:
        if len(seg_left) != 0:
            parsed_dict["left"] = seg_left
            parsed_dict["analysis"] + f"\n\n ! {len(seg_left)} BYTES OF UNPACKED DATA REMAINING"
    except UnboundLocalError:
        pass

    return parsed_dict



def parserApplication(transport_dict):
    proto = transport_dict["utility"]
    octets = transport_dict["datagram"]
    if proto == "DNS":
        application_dict = DNS(octets)
    elif proto == "DHCP":
        application_dict = DHCP(octets)
    return application_dict


