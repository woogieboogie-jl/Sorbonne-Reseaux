#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Dec  3 19:23:39 2021

@author: paulamendez
"""

#DNS messages

#only use if DNS = True

octects = ['0F','04','78','56','07','03','20','44','56','78','56','38','92','00','92','20','60','56','78','56','00','03','00','56','04','56','38','92','08','08','D4']

def DNS(octects):
    #Identification
    I = hex(int(octects[0]+octects[1],16))
    
    #Control
    C = octects[2]+octects[3]
    
    #Question count
    QC = octects[4] + octects[5]
    
    #Answer count
    AC = octects[6]+octects[7]
    
    #Authority count
    AUC = octects[8]+octects[9]
    
    #Additional count
    ADC = octects[10]+octects[11]
    
    
    #Questions
    
    
    #Answers
    
DNS(octects)


def DHCP(octects):
    
    op = int(octects[0],16)
    if op == 1:
        op = 'DHCP Request Message'
    elif op == 2:
        op = 'DHCP Reply Message'
    else:
        op = 'Unknown type of message'
    
    htype = octects[1]
    
    hlen = octects[2]
    
    hops = octects[3]
    
    xid = octects[4]+octects[5]+octects[6]+octects[7]
    
    secs = octects[8]+octects[9]
    
    flags = octects[10]+octects[11]
    
    ciadrr = octects[12:15]
             
    yiadrr = octects[16:19]
    
    siadrr = octects[20:23]
    
    giaddr = octects[24:27]
    
    chaddr = octects[28:44]
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

