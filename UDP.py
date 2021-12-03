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
    
    #Source Port
    SP = int(octects[0] + octects[1],16)
    print("Source Port:",SP)
    
    #Destination Port
    DP = int(octects[2]+octects[3],16)
    print("Destination Port:",DP)
    
    #Length
    L = int(octects[4]+octects[5],16)
    print(f"Length: {L} octects.")
    
    #Checksum
    
    
    