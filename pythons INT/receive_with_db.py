#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct

from time import sleep
from scapy.all import Packet, bind_layers, BitField, ShortField, IntField, Ether, IP, UDP, sendp, get_if_hwaddr, sniff, PacketListField

import os, time
from influxdb_client_3 import InfluxDBClient3, Point


class InBandNetworkTelemetry(Packet):
    fields_desc = [
        BitField("switchID_t", 0, 31),
        BitField("ingress_port", 0, 9),
        BitField("egress_port", 0, 9),
        BitField("egress_spec", 0, 9),
        BitField("ingress_global_timestamp", 0, 48),
        BitField("egress_global_timestamp", 0, 48),
        BitField("enq_timestamp", 0, 32),
        BitField("enq_qdepth", 0, 19),
        BitField("deq_timedelta", 0, 32),
        BitField("deq_qdepth", 0, 19)
    ]
    """any thing after this packet is extracted is padding"""

    def extract_padding(self, p):
        return "", p


class NodeCount(Packet):
    name = "nodeCount"
    fields_desc = [ShortField("count", 0),
                   PacketListField("INT", [], InBandNetworkTelemetry, count_from=lambda pkt: (pkt.count * 1))]


def handle_pkt(pkt, client, database):
    # pkt.show2()
    if NodeCount in pkt:
        for int_pkt in pkt[NodeCount].INT:
            telemetry = int_pkt[InBandNetworkTelemetry]
            print("Packet - INT Header:")
            print()
            print("Switch ID:", telemetry.switchID_t)
            # print("Egress Port:", telemetry.egress_port)
            # print("Egress Spec:", telemetry.egress_spec)
            print("Ingress Global Timestamp:", telemetry.ingress_global_timestamp)
            print("Egress Global Timestamp:", telemetry.egress_global_timestamp)
            print("Enqueue Timestamp:", telemetry.enq_timestamp)
            print("Enqueue Queue Depth:", telemetry.enq_qdepth)
            print("Dequeue Timedelta:", telemetry.deq_timedelta)
            print("Dequeue Queue Depth:", telemetry.deq_qdepth)

            print("------------------------------")
            point = (
                Point("INT")
                .tag("Jogo", "Fortnite-T")
                .field("Enq. Queue Depth", telemetry.enq_qdepth)
                .field("Deq. Queue Depth", telemetry.deq_qdepth)
                .field("Deq. Timedelta", telemetry.deq_timedelta)
            )
            client.write(database=database, record=point)


def connectDB():
    token = os.environ.get("INFLUXDB_TOKEN")
    org = "Research"
    host = "https://us-east-1-1.aws.cloud2.influxdata.com"

    client = InfluxDBClient3(host=host, token=token, org=org)
    return client


def main():
    client = connectDB()
    database = "CG-Monitoramento"

    iface = 'Wi-Fi'  # interface de entrada, alterar para Ethernet quando necessário

    bind_layers(IP, NodeCount, proto=253)  # Correção na nomenclatura da classe
    bind_layers(Ether, IP)

    sniff(filter="ip proto 253", iface=iface, prn=lambda x: handle_pkt(x, client, database))


if __name__ == '__main__':
    main()
