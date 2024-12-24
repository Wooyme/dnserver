import logging
import sys
from logging.handlers import TimedRotatingFileHandler
import paho.mqtt.client as mqtt

import dnslib
from dnslib import DNSRecord, RR, QTYPE
from dnslib.server import DNSHandler
from redis import Redis

redis_client = Redis()


# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print(f"Connected with result code {rc}")
    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    # client.subscribe("$SYS/#")
    client.publish("/dns_server/startup", "Hello")


# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))


mqttc = mqtt.Client()
mqttc.on_connect = on_connect
mqttc.on_message = on_message
mqttc.username_pw_set('core', 'c0re_22yun_0rg')
mqttc.connect("core.zzyun.org", 1883, 60)
mqttc.loop_start()


def setup_logger():
    # 创建一个logger
    logger = logging.getLogger('dns_query')
    logger.setLevel(logging.DEBUG)  # 可以根据需要设置为DEBUG, INFO, WARNING等

    # 创建一个handler，用于输出到控制台
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_format)

    # 创建一个handler，用于写入日志文件，按天轮换
    file_handler = TimedRotatingFileHandler('dns_query.log', when='midnight', interval=1)
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)
    file_handler.suffix = "%Y-%m-%d"  # 设置文件名后缀，显示为年-月-日

    # 添加handler到logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


logger = setup_logger()


class EnhancedDNSHandler(DNSHandler):
    def get_reply(self, data):
        request = DNSRecord.parse(data)
        logger.info(f"{self.client_address[0]} {request.q.qname}")
        client_ip = self.client_address[0]
        if redis_client.exists('dld-' + client_ip):
            rr = RR(
                rname=request.q.qname.label,
                rtype=QTYPE.A,
                rdata=dnslib.A('1.2.3.4'),
                ttl=300,
            )
            reply = request.reply()
            reply.add_answer(rr)
            if self.protocol == 'udp':
                rdata = reply.pack()
                if self.udplen and len(rdata) > self.udplen:
                    truncated_reply = reply.truncate()
                    rdata = truncated_reply.pack()
            else:
                rdata = reply.pack()
            mqttc.publish("/dns_server/query", f"{client_ip} {request.q.qname}")
            return rdata
        else:
            logger.info(f"Illegal IP request: {client_ip}")
            return b'\x00'
