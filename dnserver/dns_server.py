import logging

from dnslib.server import DNSHandler
from redis import Redis

redis_client = Redis()

def get_handler(logger):
    class EnhancedDNSHandler(DNSHandler):
        def get_reply(self, data):
            client_ip = self.client_address[0]
            if redis_client.exists('dld-' + client_ip):
                return super().get_reply(data)
            else:
                logger.info(f"Illegal IP request: {client_ip}")
                return b'\x00'
    return EnhancedDNSHandler
