#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Dec  3 19:23:39 2021

@author: paulamendez
"""

#DNS messages

#sources to find format and values:
    #http://www-inf.int-evry.fr/~hennequi/CoursDNS/NOTES-COURS_eng/msg.html
    #https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
    #https://spathis.medium.com/comprendre-internet-et-son-fonctionnement-9b2f63a07430
    #https://en.wikipedia.org/wiki/Domain_Name_System#DNS_message_format

#only use if DNS = True

octects = ['0F','04','78','56','07','03','20','44','56','78','56','38','92','00','92','20','60','56','78','56','00','03','00','56','04','56','38','92','08','08','D4']

def Identification(octects):
    #Identification
    I = hex(int(octects[0]+octects[1],16))
    return f"The identification is: {I}"
    
def Control(octects):
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
    else:
        TC = 'Not truncated'
    RD = C[7]           #Recursion Desired
    RD_dic = {0:'Iterative', 1:'Recursif'}
    RA = C[8]           #Recursion Available
    RA_dic = {0: 'Server does not manage recursive', 1:'Server manages recursive'}
    Z = C[9]            #Zero reserved for extensions
    if Z == 0:
        Z = 'Reserved for extensions'
    AD = [10]           #Authenticated Data
    CD = [11]           #Checking Disabled
    Rcode = [12]
    Rcode_dic = {0:'NOERROR', 1:'FORMERR', 2:'SERVFAIL', 3:'NXDOMAIN', 4:'NOTIMP', 5:'REFUSED', 6:'YXDOMAIN', 7:'XRRSET', 8:'NOTAUTH', 9:'NOTZONE' }
    return f"Control:\n \tMessage is a {QR_dic[QR]} \n\t The type of request is {OpCode_dic.get(OpCode, 'Unknown')} \n\t \
            Reply from {AA_dic[AA]} \n\t {TC} \n\t {RD_dic[RD]} Response \n\t {RA_dic[RA]} \n\t {Z} \n\t \
            {AD}: Authenticated Data \n\t {CD}: Checking Disabled \n\t Error Codes: {Rcode_dic.get(Rcode, 'Unknown')} "
            
def QuestionC(octects):   
    #Question count
    QC = int(octects[4] + octects[5],16)
    return f"The number of Questions is {QC}", QC

def AnswerC(octects):
    #Answer count
    AC = int(octects[6]+octects[7],16)
    return f"The number of Answers is {AC}", AC
    
def AuthorityC(octects):
    #Authority count
    AUC = int(octects[8]+octects[9],16)
    return f"The number of Authority Resource Records (RR's) is {AUC}", AUC
    
def AdditionalC(octects):
    #Additional count
    ADC = int(octects[10]+octects[11],16)
    return f"The number if additional RRs is {ADC}" , ADC 
    
    #DNS contains Resouce Records: RR
    #(NAME, VALUE, TYPE, TTL)
    
    
def Questions(octects):
    TypeRR = {1: 'A', 28: 'AAAA', 5: 'CNAME', 2: 'NS', 15: 'MX'}
    octects = octects[12:]
    #name, type, class
    #length of name is unknown, name is made of labels whose length is indicated by the first octect
    #label end of name is 00
    i = 0
    Q = ''
    while octects[i] != '00': 
        Q += octects[i]
        i = i + 1
    Q = hex(int(Q,16))
    T = octects[i:i+2]
    T = TypeRR.get(T, 'Unknown')
    C = int(octects[i+2:i+4],16)
    C = hex(C)
    octects=octects[i+34:]
    return f"Questions: \n\t Nom de domaine: {Q} \n\t Type d'enregistrement: {T} \n\t Class: {C}", octects
    #it has to returned the chopped list without the questions as well so its easy to implement again the loop
    #for the name :)
    
def Answers(octects): 
    TypeRR = {1: 'A', 28: 'AAAA', 5: 'CNAME', 2: 'NS', 15: 'MX'}
    #name, type, class, ttl, rdata_length, rdata
    #length of name is unknown, name is made of labels whose length is indicated by the first octect
    #label end of name is 00
    i = 0
    Q = ''
    while octects[i] != '00': 
        Q += octects[i]
        i = i + 1
    Q = hex(int(Q,16))
    T = octects[i:i+2]
    T = TypeRR.get(T, 'Unknown')
    C = int(octects[i+2:i+4],16)
    C = hex(C)
    TTL = int(octects[i+4:i+8],16)
    Rdata_length = int(octects[i+8,i+10],16)
    Rdata = hex(int(octects[i+10:i+10+Rdata_length],16))
    octects = octects[i+10+Rdata_length:]
    return f"Answers: \n\t Nom de domaine: {Q} \n\t Type d'enregistrement: {T} \n\t Class: {C} \n\t TTL: {TTL} \
            \n\t Length Data: {Rdata_length} \n\t Data: {Rdata}", octects
    
def Authority(octects):
    #Authority 
    TypeRR = {1: 'A', 28: 'AAAA', 5: 'CNAME', 2: 'NS', 15: 'MX'}
    #name, type, class, ttl, rdata_length, rdata
    #length of name is unknown, name is made of labels whose length is indicated by the first octect
    #label end of name is 00
    i = 0
    Q = ''
    while octects[i] != '00': 
        Q += octects[i]
        i = i + 1
    Q = hex(int(Q,16))
    T = octects[i:i+2]
    T = TypeRR.get(T, 'Unknown')
    C = int(octects[i+2:i+4],16)
    C = hex(C)
    TTL = int(octects[i+4:i+8],16)
    Rdata_length = int(octects[i+8,i+10],16)
    Rdata = hex(int(octects[i+10:i+10+Rdata_length],16))
    octects = octects[i+10+Rdata_length:]
    return f"Authority: \n\t Nom de domaine: {Q} \n\t Type d'enregistrement: {T} \n\t Class: {C} \n\t TTL: {TTL} \
            \n\t Length Data: {Rdata_length} \n\t Data: {Rdata}", octects
    
    
def Additional(octects):
    #Additional
    TypeRR = {1: 'A', 28: 'AAAA', 5: 'CNAME', 2: 'NS', 15: 'MX'}
    #name, type, class, ttl, rdata_length, rdata
    #length of name is unknown, name is made of labels whose length is indicated by the first octect
    #label end of name is 00
    i = 0
    Q = ''
    while octects[i] != '00': 
        Q += octects[i]
        i = i + 1
    Q = hex(int(Q,16))
    T = octects[i:i+2]
    T = TypeRR.get(T, 'Unknown')
    C = int(octects[i+2:i+4],16)
    C = hex(C)
    TTL = int(octects[i+4:i+8],16)
    Rdata_length = int(octects[i+8,i+10],16)
    Rdata = hex(int(octects[i+10:i+10+Rdata_length],16))
    octects = octects[i+10+Rdata_length:]
    return f"Additional: \n\t Nom de domaine: {Q} \n\t Type d'enregistrement: {T} \n\t Class: {C} \n\t TTL: {TTL} \
            \n\t Length Data: {Rdata_length} \n\t Data: {Rdata}", octects
    
    
    
def DNS(octects):
    #Identification
    Identification(octects)
    
    #Control
    Control(octects)
    
    #Question count
    QuestionC(octects)
    
    #Answer count
    AnswerC(octects)
    
    #Authority Count
    AuthorityC(octects)
    
    #Additional Count
    AdditionalC(octects)
    
    #Questions
    Questions(octects)
    
    #Answers
    Answers(octects)
    
    #Authority
    Authority(octects)
    
    #Additional
    Additional(octects)
    
    return 



    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

