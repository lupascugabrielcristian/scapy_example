from scapy.all import *
import sys
import os

def stop_sniff_filter(packet, questions):
    if packet[DNS].qr == 1 and packet[DNS].ancount > 0:
        print("FINISHED")
        return True
    else:
        print("NOT finished")
        return False

def print_records(packet):
    try:
        print("IP: %s" % packet[DNS].an.rdata)
    except TypeError as e:
        print("Error: %s" % e)
    except AttributeError as e2:
        print("No attribute an: %s" % e2)

def look_for_dns_exchange(packet, questions):
    if DNS in packet and packet.qr == 1:
        print("Got DNS response for id %s" % packet[DNS].id)
        if packet[DNS].ancount > 0:
            print_records(packet)
    if DNS in packet and packet.qr == 0:
        questions.append(packet)
        print("Got a DNS request with id %s" % packet[DNS].id)

def create_DNS_response():
    dns_response = IP(dst="192.168.56.116", src="192.168.56.117")/UDP(dport=53, sport=54345)/DNS()
    return dns_response

def look_for_test_dns_requests(packet):
    if DNS in packet and packet.qr == 0:
        if "www.google.com" in packet[DNS].qd.qname.decode('utf8'):
            print("Got request. Sending fake response")
            response = create_DNS_response()
            sr(response)
        else:
            print("Got a request for another site")


def look():
    questions = []
    print("Start sniffing for real packets on interface %s" % real_interface)
    sniff(iface=real_interface, promisc=1, prn=lambda packet: look_for_dns_exchange(packet, questions), stop_filter=lambda packet: stop_sniff_filter(packet, questions))
    print("Got original package")
    print("Waitng for DNS request on interface (%s)" % mock_interface)
    sniff(iface=mock_interface, promisc=1, prn=lambda packet: look_for_test_dns_requests(packet))

if os.geteuid() != 0:
    print("Run as root")
    exit()
else:
    print("OK")

#real_interface = input("interface for real packets: ")
real_interface = "enp0s3"
#mock_interface = input("interface for testing packets: ")
mock_interface = "enp0s8"

look()
