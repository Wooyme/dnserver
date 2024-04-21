from dnslib.server import DNSHandler
from redis import Redis

redis_client = Redis()


class EnhancedDNSHandler(DNSHandler):
    def get_reply(self, data):
        client_ip = self.client_address[0]
        if redis_client.exists('leg-' + client_ip):
            return super().get_reply(data)
        else:
            return b'\x00'
