"""
################################################################################
#                                                                              #
#                              Xer0x's Codebase                                #
#                                                                              #
#   This code is the property of Xer0x (https://xer0x.in) and is released      #
#   under the Creative Commons Attribution-NoDerivs 4.0 International License. #
#   Redistribution of this work is allowed, provided proper credit is given.   #
#   HOWEVER, NO MODIFICATIONS OR DERIVATIVE WORKS ARE PERMITTED.               #
#                                                                              #
#   License: CC BY-ND 4.0                                                      #
#   Details: https://creativecommons.org/licenses/by-nd/4.0/                   #
#                                                                              #
#   Author: Xer0x                                                              #
#   Website: https://xer0x.in                                                  #
#                                                                              #
################################################################################
"""


import socket
import struct
import random
import threading
import time
from collections import OrderedDict
import urllib.request
import os
import hashlib

DNS_SERVER = '9.9.9.9'  # Default upstream DNS server
BLOCKLIST_URLS = [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro-compressed.txt',
]
BLOCKLIST_CACHE_DIR = 'blocklist_cache'
BLOCKLIST_CACHE_TTL = 24 * 60 * 60  # 24 hours

class BlocklistCache:
    def __init__(self):
        self.blocked_domains = set()
        self.last_update = 0
        self.lock = threading.Lock()
        self.cache_dir = BLOCKLIST_CACHE_DIR
        os.makedirs(self.cache_dir, exist_ok=True)
        
    def _get_cache_path(self, url):
        """Generate a cache file path for a given URL."""
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"blocklist_{url_hash}.txt")

    def _is_cache_valid(self, cache_path):
        """Check if the cache file is still valid."""
        if not os.path.exists(cache_path):
            return False
        cache_age = time.time() - os.path.getmtime(cache_path)
        return cache_age < BLOCKLIST_CACHE_TTL

    def _download_and_cache_blocklist(self, url):
        """Download and cache a blocklist."""
        cache_path = self._get_cache_path(url)
        
        try:
            if self._is_cache_valid(cache_path):
                with open(cache_path, 'r') as f:
                    return f.readlines()
                    
            response = urllib.request.urlopen(url)
            content = response.read().decode('utf-8').splitlines()
            
            with open(cache_path, 'w') as f:
                f.write('\n'.join(content))
                
            return content
        except Exception as e:
            print(f"Error downloading blocklist {url}: {e}")
            if os.path.exists(cache_path):
                with open(cache_path, 'r') as f:
                    return f.readlines()
            return []

    def update_blocklists(self):
        """Update blocklists from all sources."""
        with self.lock:
            new_blocked_domains = set()
            
            for url in BLOCKLIST_URLS:
                content = self._download_and_cache_blocklist(url)
                
                for line in content:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            # Handle hosts file format (0.0.0.0 domain.com or 127.0.0.1 domain.com)
                            parts = line.split()
                            if len(parts) >= 2 and (parts[0] == '0.0.0.0' or parts[0] == '127.0.0.1'):
                                domain = parts[1].lower()
                                new_blocked_domains.add(domain)
                        except Exception:
                            continue

            self.blocked_domains = new_blocked_domains
            self.last_update = time.time()

    def is_blocked(self, domain):
        """Check if a domain is blocked."""
        current_time = time.time()
        if current_time - self.last_update > BLOCKLIST_CACHE_TTL:
            threading.Thread(target=self.update_blocklists).start()
        
        return domain.lower() in self.blocked_domains

class DNSCache:
    def __init__(self, max_size=200 * 1024 * 1024):  # 200 MB limit
        self.cache = OrderedDict()
        self.lock = threading.Lock()
        self.current_size = 0
        self.max_size = max_size

    def _calculate_entry_size(self, key, value):
        return len(key) + len(value)

    def set(self, key, value, ttl):
        """Add a DNS response to the cache."""
        with self.lock:
            now = time.time()
            expiration = now + ttl
            entry_size = self._calculate_entry_size(key, value)

            while self.current_size + entry_size > self.max_size:
                self._evict_oldest()

            self.cache[key] = (value, expiration)
            self.cache.move_to_end(key)
            self.current_size += entry_size

    def get(self, key):
        """Retrieve a DNS response from the cache."""
        with self.lock:
            now = time.time()
            if key in self.cache:
                value, expiration = self.cache[key]
                if expiration > now:
                    self.cache.move_to_end(key)
                    return value
                else:
                    del self.cache[key]
                    self.current_size -= self._calculate_entry_size(key, value)
        return None

    def _evict_oldest(self):
        """Evict the oldest entry in the cache."""
        if self.cache:
            key, (value, _) = self.cache.popitem(last=False)
            self.current_size -= self._calculate_entry_size(key, value)

def build_query(domain, query_type):
    """Build a DNS query packet."""
    transaction_id = random.randint(0, 65535)
    flags = 0x0100
    qdcount = 1
    header = struct.pack(">HHHHHH", transaction_id, flags, qdcount, 0, 0, 0)

    query = b""
    for part in domain.split('.'):
        query += bytes([len(part)]) + part.encode()
    query += b'\x00'

    qclass = 1
    question = query + struct.pack(">HH", query_type, qclass)

    return header + question, transaction_id

def parse_query(data):
    """Parse the DNS query."""
    try:
        offset = 12  # DNS header is 12 bytes
        domain_parts = []
        while data[offset] != 0:
            length = data[offset]
            domain_parts.append(data[offset + 1:offset + 1 + length].decode())
            offset += length + 1
        domain = ".".join(domain_parts)
        query_type, query_class = struct.unpack(">HH", data[offset + 1:offset + 5])
        return domain, query_type
    except Exception as e:
        print(f"Error parsing query: {e}")
        return None, None

def parse_response(data):
    """Parse DNS response packet."""
    def parse_name(data, offset):
        labels = []
        while True:
            length = data[offset]
            if length & 0xC0 == 0xC0:
                pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
                labels.append(parse_name(data, pointer)[0])
                offset += 2
                break
            elif length == 0:
                offset += 1
                break
            else:
                offset += 1
                labels.append(data[offset:offset + length].decode())
                offset += length
        return ".".join(labels), offset

    def parse_soa(data, offset):
        mname, offset = parse_name(data, offset)
        rname, offset = parse_name(data, offset)
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[offset:offset + 20])
        offset += 20
        return {
            'mname': mname,
            'rname': rname,
            'serial': serial,
            'refresh': refresh,
            'retry': retry,
            'expire': expire,
            'minimum': minimum,
        }, offset

    results = {'answers': [], 'authority': [], 'additional': []}
    offset = 12
    try:
        qdcount, ancount, nscount, arcount = struct.unpack(">HHHH", data[4:12])
    except struct.error as e:
        print(f"Header unpack error: {e}")
        return results

    for _ in range(qdcount):
        _, offset = parse_name(data, offset)
        offset += 4  # Skip QTYPE and QCLASS

    def parse_record(offset, count, section_name):
        for _ in range(count):
            name, offset = parse_name(data, offset)
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            offset += rdlength

            if rtype == 1:  # A record
                results[section_name].append((name, 'A', ttl, socket.inet_ntoa(rdata)))
            elif rtype == 28:  # AAAA record
                results[section_name].append((name, 'AAAA', ttl, socket.inet_ntop(socket.AF_INET6, rdata)))
            elif rtype == 5:  # CNAME record
                cname, _ = parse_name(data, offset - rdlength)
                results[section_name].append((name, 'CNAME', ttl, cname))
            elif rtype == 6:  # SOA record
                soa, _ = parse_soa(data, offset - rdlength)
                results[section_name].append((name, 'SOA', ttl, soa))
            elif rtype == 15:  # MX record
                preference, = struct.unpack(">H", rdata[:2])
                exchange, _ = parse_name(data, offset - rdlength + 2)
                results[section_name].append((name, 'MX', ttl, {'preference': preference, 'exchange': exchange}))
            elif rtype == 16:  # TXT record
                txt = rdata[1:].decode()
                results[section_name].append((name, 'TXT', ttl, txt))
            elif rtype == 2:  # NS record
                ns, _ = parse_name(data, offset - rdlength)
                results[section_name].append((name, 'NS', ttl, ns))
        return offset

    offset = parse_record(offset, ancount, 'answers')
    offset = parse_record(offset, nscount, 'authority')
    parse_record(offset, arcount, 'additional')

    return results

def query_upstream(domain, query_type):
    """Query upstream DNS server."""
    query, _ = build_query(domain, query_type)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    try:
        sock.sendto(query, (DNS_SERVER, 53))
        data, _ = sock.recvfrom(512)
        return data
    finally:
        sock.close()

def get_blocked_response(transaction_id):
    """Generate a DNS response for blocked domains."""
    flags = 0x8183  # Standard response, NXDOMAIN
    counts = (1, 0, 0, 0)  # QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    header = struct.pack('>HHHHHH', transaction_id, flags, *counts)
    return header

# Initialize global caches
dns_cache = DNSCache()
blocklist_cache = BlocklistCache()

def handle_client(server_socket):
    """Handle incoming DNS queries."""
    try:
        data, client_addr = server_socket.recvfrom(512)
        client_transaction_id = struct.unpack(">H", data[:2])[0]
        domain, query_type = parse_query(data)

        if not domain:
            print(f"Invalid query from {client_addr}")
            return

        # Check if domain is blocked
        if blocklist_cache.is_blocked(domain):
            response = get_blocked_response(client_transaction_id)
            server_socket.sendto(response, client_addr)
            return

        cache_key = f"{domain}:{query_type}"
        cached_response = dns_cache.get(cache_key)
        if cached_response:
            response = cached_response
        else:
            response = query_upstream(domain, query_type)
            parsed_response = parse_response(response)
            if parsed_response:
                ttl = 300  # 5 minutes default TTL
                dns_cache.set(cache_key, response, ttl)

        response = struct.pack(">H", client_transaction_id) + response[2:]
        server_socket.sendto(response, client_addr)
    except Exception as e:
        print(f"Error handling client: {e}")

def start_server():
    """Start the DNS server."""
    # Initialize blocklist cache
    print("Initializing blocklist cache...")
    blocklist_cache.update_blocklists()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 853))

    print("DNS server running on port 853...")
    while True:
        handle_client(server_socket)

if __name__ == "__main__":
    start_server()

