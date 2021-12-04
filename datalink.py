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



octects = ['F0','56','78','56','38','92','20','60','56','78','56','38','92','00','92','20','60','56','78','56','38','92','00','56','78','56','38','92','00']


def datalink_parser(octects):

    #version
    version = int(str(octects[0])[:1],16)
    print("Version:", version)
    
    #IHL
    IHL = int(str(octects[0])[1:],16)
    print("IP Header Length:", IHL*4, "octects.")
    
    #TOS
    TOS = int(octects[1],16)
    print("Type Of Service:", TOS)
    
    #Total Length
    TL = int(octects[2] + octects[3], 16)
    print("Longueur totale:", TL, "octects.")
    
    #Identification
    ID = int(octects[4]+ octects[5], 16)
    print("Identification:", ID)
    
    #Flags
    F = str(octects[6])[:1]
    F = "{0:04b}".format(int(F, 16))
    R = F[:1]
    DF = F[1:2]
    MF = F[2:3]
    print("The flags have the following values:")
    print("\tThe first bit is reserved with a value of", R)
    print("\tDon't Fragment:", DF)
    print("\tMore Fragment", MF)
    
    #Fragment offset
    FO = F[3:4] + "{0:04b}".format(int(str(octects[6])[1:], 16)) + "{0:08b}".format(int(str(octects[7]), 16))
    FO = int(FO,2)          #en unités de 64 bits
    FO = FO * 8             #en octects
    print("Fragment Offset:", FO, "octects.")

    #TTL
    TTL = int(octects[8],16)
    print("Time To Live:",TTL)
    
    #Protocol
    UDP = False
    IPProtocols = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 36: 'XTP', 46: 'RSVP'}
    P = int(octects[9],16)
    if P == 17:
        UDP = True
    if "P" in IPProtocols:
        P = IPProtocols[P]
        print("Le Protocole utilisé c'est le:", P)
    else: 
        print("Protocole unconu.")
        
    #Header checksum #change to hexa
    HC = int(octects[10] + octects[11], 16)         #HC en decimal
    HC = bin(HC)
    print("Checksum:", HC)
    #possible:verifier si le checksum est correct
    
    #Source Address
    SA1 = int(octects[12],16)
    SA2 = int(octects[13],16)
    SA3 = int(octects[14],16)
    SA4 = int(octects[15],16)
    print(f"Source Adress: {SA1}.{SA2}.{SA3}.{SA4}")
    
    #Destination Address
    DA1 = int(octects[16],16)
    DA2 = int(octects[17],16)
    DA3 = int(octects[18],16)
    DA4 = int(octects[19],16)
    print(f"Destination Adress: {SA1}.{SA2}.{SA3}.{SA4}")
    
    #Options
    if IHL == 5:
        print("Il n'y a pas d'options.")

    Options = {0: 'End of Options List (EOOL)', 1: 'No Operation (NOP)', 7: 'Record Route (RR)',
               68: 'Time Stamp (TS)', 131: 'Loose Source Route (LSR)', 137: 'Strict Source Route (SSR)'}
    O = int(octects[20],16)
    if "O" in Options:
        O = Options[O]
        print("Option")
        
    

    




