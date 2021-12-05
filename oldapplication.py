#only use if DNS = True
octects = ['0F','04','78','56','07','03','20','44','56','78','56','38','92','00','92','20','60','56','78','56','00','03','00','56','04','56','38','92','08','08','D4']

def DNS(octects):
    #Identification
    I = hex(int(octects[0]+octects[1],16))
    
    #Control
    C = bin(int(octects[2]+octects[3],16))[2:]
    QR = C[0]
    QR_dic = {0: 'Request', 1: 'Response'}
    OpCode = int(C[1:5],2)
    OpCode_dic = {0: 'Query', 1: 'Inverse Query', 2:'Status', 3:'Unassigned', 4:'Notify', 5:'Update', 6:'DNS Stateful Operations'}
    AA = C[5]           #Authoritative Answer
    AA_dic = {1: 'Authoritative', 0: 'Cache'}
    TC = C[6]           #Truncated
    if TC == 1:
        TC = 'Response too large for UDP'
    RD = C[7]           #Recursion Desired
    RD_dic = {0:'Iterative', 1:'Recursif'}
    RA = C[8]           #Recursion Available
    RA_dic = {0: 'Not recursive', 1:'Recursive'}
    Z = C[9]            #Zero reserved for extensions
    AD = [10]           #Authenticated Data
    CD = [11]           #Checking Disabled
    Rcode = [12]
    Rcode_dic = {0:'NOERROR', 1:'FORMERR', 2:'SERVFAIL', 3:'NXDOMAIN', 4:'NOTIMP', 5:'REFUSED', 6:'YXDOMAIN', 7:'XRRSET', 8:'NOTAUTH', 9:'NOTZONE' }
    
    #Question count
    QC = int(octects[4] + octects[5],16)
    
    #Answer count
    AC = int(octects[6]+octects[7],16)
    
    #Authority count
    AUC = int(octects[8]+octects[9],16)
    
    #Additional count
    ADC = int(octects[10]+octects[11],16)
    
    #DNS contains Resouce Records: RR
    #(NAME, VALUE, TYPE, TTL)
    
    
    #Questions
    
    
    #Answers
    
    #Authority 
    
    
    
    #Additional
    
    
    #Print everything
    
    
    
    
    
DNS(octects)




# def DHCP(octets):
    
#     op = int(octets[0],16)
#     if op == 1:
#         op = 'DHCP Request Client'
#     elif op == 2:
#         op = 'DHCP Reply Serveur'
#     else:
#         op = 'Unknown type of message'
    
#     htype = octets[1]
    
#     hlen = octets[2]
    
#     hops = octets[3]
    
#     xid = octets[4]+octets[5]+octets[6]+octets[7]
    
#     secs = octets[8]+octets[9]
    
#     flags = octets[10]+octets[11]
    
#     ciadrr = octets[12:15]
             
#     yiadrr = octets[16:19]
    
#     siadrr = octets[20:23]
    
#     giaddr = octets[24:27]
    
#     chaddr = octets[28:44]
    
#     #je ne suis pas sure avec ce que je dois faire avec les champs de sname et file parceque qu'ils sont optionnels
    
#     Options = octects[45:]
    
#     Opt53 = {1: "DHCP Discover", 2:"DHCP Offer", 3:"DHCP Request", 4:"DHCP Decline", 5:"DHCP Pack", 6:"DHCP Nak", 7:"DHCP Release", 8:"DHCP Inform"}
    
#     #on doit toujours finir la zone d’options par une option 255
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

