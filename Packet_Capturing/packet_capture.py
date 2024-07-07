#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul  6 09:55:56 2024

@author: zanonymous
"""
from scapy.all import sniff
import threading

def packet_callback(packet):
    return format_packet(packet)

def format_packet(packet):
    packet_info = []
    if packet.haslayer('Ether'):
        eth_layer = packet.getlayer('Ether')
        packet_info.append(f"###[ Ethernet ]###")
        packet_info.append(f"  dst       = {eth_layer.dst}")
        packet_info.append(f"  src       = {eth_layer.src}")
        packet_info.append(f"  type      = {eth_layer.type}")
    
    if packet.haslayer('IP'):
        ip_layer = packet.getlayer('IP')
        packet_info.append(f"###[ IP ]###")
        packet_info.append(f"     version   = {ip_layer.version}")
        packet_info.append(f"     ihl       = {ip_layer.ihl}")
        packet_info.append(f"     tos       = {ip_layer.tos}")
        packet_info.append(f"     len       = {ip_layer.len}")
        packet_info.append(f"     id        = {ip_layer.id}")
        packet_info.append(f"     flags     = {ip_layer.flags}")
        packet_info.append(f"     frag      = {ip_layer.frag}")
        packet_info.append(f"     ttl       = {ip_layer.ttl}")
        packet_info.append(f"     proto     = {ip_layer.proto}")
        packet_info.append(f"     chksum    = {ip_layer.chksum}")
        packet_info.append(f"     src       = {ip_layer.src}")
        packet_info.append(f"     dst       = {ip_layer.dst}")
        packet_info.append(f"     options   = {ip_layer.options}")
    
    if packet.haslayer('TCP'):
        tcp_layer = packet.getlayer('TCP')
        packet_info.append(f"###[ TCP ]###")
        packet_info.append(f"        sport     = {tcp_layer.sport}")
        packet_info.append(f"        dport     = {tcp_layer.dport}")
        packet_info.append(f"        seq       = {tcp_layer.seq}")
        packet_info.append(f"        ack       = {tcp_layer.ack}")
        packet_info.append(f"        dataofs   = {tcp_layer.dataofs}")
        packet_info.append(f"        reserved  = {tcp_layer.reserved}")
        packet_info.append(f"        flags     = {tcp_layer.flags}")
        packet_info.append(f"        window    = {tcp_layer.window}")
        packet_info.append(f"        chksum    = {tcp_layer.chksum}")
        packet_info.append(f"        urgptr    = {tcp_layer.urgptr}")
        packet_info.append(f"        options   = {tcp_layer.options}")
    
    
    return "\n".join(packet_info)

def start_sniffing(callback):
    sniff(prn=callback, count=10)
