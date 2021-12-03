#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Nov 28 16:25:55 2021

@author: paulamendez
"""

#project Résaux: couche Réseaux


octects = ['0F','04','78','56','07','03','20','44','56','78','56','38','92','00','92','20','60','56','78','56','00','03','00','56','04','56','38','92','08','08','D4']

def IPOptions(octects):
    Opts = { 0: "End of Options List (EOOL)", 1: "No Operation (NOP)", 7: "Record Route (RR)", 68: "Time Stamp (TS)", 131: "Loose Source Route (LSR)", 137: "Strict Source Route (SSR)"}
    while len(octects) > 0 :
        o = int(octects[0],16)
        Opt = Opts.get(o, "Option unconnu")
        print(f"\t{o}: {Opt}.")
        if o == 0:  #im not quite suere about how the EOOL works or padding either, need to consult this
            break
        else:
            L = octects[1]
            L_dec = int(L,16)
            print("\t\tLa longueur de l'option est de", L_dec, "octects.")
            V = octects[2:L_dec]
            V = ''.join(V)
            V = hex(int(V,16))
            print("\t\tLa valeur de l'option est", V)
            octects = octects[L_dec:]
            

#Function IP is gonna return a directory with first the new octect list
#we use in the next levels and second the UDP true or false

def IP(octects):
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
    ID = "{0:04x}".format(int(octects[4]+ octects[5], 16))
    print(f"Identification: 0x{ID}")
    
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
        
    #Header checksum 
    HC = int(octects[10] + octects[11], 16)         
    HC = hex(HC)
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
    print(f"Destination Adress: {DA1}.{DA2}.{DA3}.{DA4}")
    
    #Options+padding
    print("Options:")
    if IHL == 5:
        print("\tIl n'y a pas d'options.")
        
    Options_octects = octects[20:IHL*4]
    IPOptions(Options_octects)
    
    #Dictionary with response
    trimmed_octects = octects[IHL*4:]     #Octetcs without the IP header
    ResultIP = {1:trimmed_octects,2:UDP}

    return ResultIP
    
        
    




