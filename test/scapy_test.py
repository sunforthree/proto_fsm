from scapy.all import IP, hexdump

if __name__ == '__main__':
    test_ip = IP(dst="www.slashdot.org")
    hexdump(test_ip)
    v = 4
    v <<= (4 < 5)
    print(v)