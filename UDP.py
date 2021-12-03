#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Dec  3 18:53:12 2021

@author: paulamendez
"""

#UDP

#this function will only be used if in the IP level UDP = true

octects = ['0F','04','78','56','07','03','20','44','56','78','56','38','92','00','92','20','60','56','78','56','00','03','00','56','04','56','38','92','08','08','D4']

def UDP(octects):
    print("The UDP message:")
    #Source Port
    SP = int(octects[0] + octects[1],16)
    print("\tSource Port:",SP)
    
    #Destination Port
    DP = int(octects[2]+octects[3],16)
    print("\tDestination Port:",DP)
    
    #Length
    L = int(octects[4]+octects[5],16)
    print(f"\tLength: {L} octects.")
    
    #Checksum
    C = "{0:04x}".format(int(octects[6]+octects[7],16))
    print("\tChecksum:", C)
    
    #Data
    D = ''.join(octects[8:])
    D = int(D, 16)
    print("\tData:",hex(D))
    
    
UDP(octects)