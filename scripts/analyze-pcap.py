#!/usr/bin/env python3
"""Summarize Ethernet pcaps without non-standard Python dependencies."""

import argparse
import collections
import datetime
import json
import math
import pathlib
import socket
import struct


def percentile(values, fraction):
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, math.floor((len(values) - 1) * fraction))]


def read_markers(directory):
    markers = {}
    if not directory:
        return markers
    for path in pathlib.Path(directory).iterdir():
        try:
            text = path.read_text().strip().replace("Z", "+00:00")
            markers[path.name] = datetime.datetime.fromisoformat(text).timestamp()
        except (OSError, ValueError):
            pass
    return markers


def packet_records(path):
    with path.open("rb") as stream:
        magic = stream.read(4)
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
            b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
            b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
            b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
        }
        if magic not in formats:
            raise ValueError(f"unsupported pcap magic {magic.hex()}")
        endian, divisor = formats[magic]
        header = stream.read(20)
        if len(header) != 20:
            raise ValueError("truncated pcap header")
        _, _, _, _, _, link_type = struct.unpack(endian + "HHiiii", header)
        if link_type != 1:
            raise ValueError(f"unsupported link type {link_type}; expected Ethernet")
        while True:
            header = stream.read(16)
            if not header:
                return
            if len(header) != 16:
                raise ValueError("truncated packet header")
            seconds, subseconds, captured, original = struct.unpack(endian + "IIII", header)
            data = stream.read(captured)
            if len(data) != captured:
                raise ValueError("truncated packet")
            yield seconds + subseconds / divisor, original, data


def decode_packet(data):
    if len(data) < 14:
        return {"protocol": "truncated"}
    ether_type = struct.unpack("!H", data[12:14])[0]
    offset = 14
    if ether_type in (0x8100, 0x88A8) and len(data) >= 18:
        ether_type = struct.unpack("!H", data[16:18])[0]
        offset = 18

    if ether_type == 0x0800 and len(data) >= offset + 20:
        ihl = (data[offset] & 0x0F) * 4
        protocol = data[offset + 9]
        source = socket.inet_ntop(socket.AF_INET, data[offset + 12:offset + 16])
        destination = socket.inet_ntop(socket.AF_INET, data[offset + 16:offset + 20])
        return decode_transport(data, offset + ihl, protocol, source, destination, "IPv4")
    if ether_type == 0x86DD and len(data) >= offset + 40:
        protocol = data[offset + 6]
        source = socket.inet_ntop(socket.AF_INET6, data[offset + 8:offset + 24])
        destination = socket.inet_ntop(socket.AF_INET6, data[offset + 24:offset + 40])
        return decode_transport(data, offset + 40, protocol, source, destination, "IPv6")
    return {"protocol": f"etherType-0x{ether_type:04x}"}


def decode_transport(data, offset, protocol, source, destination, network):
    result = {"protocol": network, "source": source, "destination": destination, "payload": b""}
    if protocol == 6 and len(data) >= offset + 20:
        source_port, destination_port = struct.unpack("!HH", data[offset:offset + 4])
        header_length = (data[offset + 12] >> 4) * 4
        result.update(
            protocol="TCP",
            sourcePort=source_port,
            destinationPort=destination_port,
            tcpFlags=data[offset + 13],
            payload=data[offset + header_length:],
        )
    elif protocol == 17 and len(data) >= offset + 8:
        source_port, destination_port = struct.unpack("!HH", data[offset:offset + 4])
        result.update(
            protocol="UDP",
            sourcePort=source_port,
            destinationPort=destination_port,
            payload=data[offset + 8:],
        )
    elif protocol == 58:
        result["protocol"] = "ICMPv6"
    else:
        result["protocol"] = f"{network}-next-{protocol}"
    return result


def payload_signature(protocol, payload):
    if not payload:
        return None
    if payload.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
        return "HTTP2-preface"
    if len(payload) >= 3 and payload[0] in range(0x14, 0x18) and payload[1] == 3:
        return "TLS-record"
    if b"\x00\x00\x00\x01" in payload[:64] or b"\x00\x00\x01" in payload[:64]:
        return "AnnexB-start-code"
    if protocol == "UDP" and len(payload) >= 12 and payload[0] >> 6 == 2:
        if 192 <= payload[1] <= 223:
            return f"RTCP-type-{payload[1]}"
        return f"RTP-like-pt-{payload[1] & 0x7f}"
    return None


def summarize(path, markers):
    protocols = collections.Counter()
    flows = collections.Counter()
    flow_details = {}
    directional_flows = collections.Counter()
    signatures = collections.Counter()
    prefixes = collections.Counter()
    rtp_streams = {}
    rtcp_packets = collections.Counter()
    rtcp_lengths = collections.Counter()
    rtcp_trailers = collections.Counter()
    seconds = collections.defaultdict(lambda: {"packets": 0, "bytes": 0})
    sizes = []
    first = None
    last = None

    for timestamp, original_length, raw in packet_records(path):
        first = timestamp if first is None else min(first, timestamp)
        last = timestamp if last is None else max(last, timestamp)
        sizes.append(original_length)
        decoded = decode_packet(raw)
        protocol = decoded["protocol"]
        protocols[protocol] += 1
        bucket = math.floor(timestamp)
        seconds[bucket]["packets"] += 1
        seconds[bucket]["bytes"] += original_length

        if "sourcePort" in decoded:
            source = f"[{decoded['source']}]:{decoded['sourcePort']}"
            destination = f"[{decoded['destination']}]:{decoded['destinationPort']}"
            directional_flows[f"{protocol} {source} -> {destination}"] += original_length
            pair = sorted((source, destination))
            flows[f"{protocol} {pair[0]} <-> {pair[1]}"] += original_length
            flow_name = f"{protocol} {pair[0]} <-> {pair[1]}"
            detail = flow_details.setdefault(flow_name, {
                "packets": 0, "bytesOnWire": 0, "payloadBytes": 0,
                "firstTimestamp": timestamp, "lastTimestamp": timestamp,
            })
            detail["packets"] += 1
            detail["bytesOnWire"] += original_length
            detail["payloadBytes"] += len(decoded["payload"])
            detail["firstTimestamp"] = min(detail["firstTimestamp"], timestamp)
            detail["lastTimestamp"] = max(detail["lastTimestamp"], timestamp)
            payload = decoded["payload"]
            signature = payload_signature(protocol, payload)
            if signature:
                signatures[signature] += 1
            if payload:
                prefixes[payload[:12].hex()] += 1
            if protocol == "UDP" and len(payload) >= 4 and payload[0] >> 6 == 2 and 192 <= payload[1] <= 223:
                rtcp_name = f"{source} -> {destination} type={payload[1]}"
                rtcp_packets[rtcp_name] += 1
                rtcp_lengths[f"{rtcp_name} bytes={len(payload)}"] += 1
                declared_length = (struct.unpack("!H", payload[2:4])[0] + 1) * 4
                rtcp_trailers[f"{rtcp_name} declared={declared_length} trailer={len(payload) - declared_length}"] += 1
            elif protocol == "UDP" and len(payload) >= 12 and payload[0] >> 6 == 2:
                payload_type = payload[1] & 0x7F
                sequence, rtp_timestamp, ssrc = struct.unpack("!HII", payload[2:12])
                stream_name = f"{source} -> {destination} PT={payload_type} SSRC=0x{ssrc:08x}"
                stream = rtp_streams.setdefault(stream_name, {
                    "packets": 0, "bytesOnWire": 0, "payloadBytes": 0,
                    "markerPackets": 0,
                    "firstSequence": sequence, "lastSequence": sequence,
                    "firstRTPTimestamp": rtp_timestamp, "lastRTPTimestamp": rtp_timestamp,
                    "firstTimestamp": timestamp, "lastTimestamp": timestamp,
                    "_sequences": set(), "_rtpTimestamps": set(), "_timestampSteps": collections.Counter(),
                })
                stream["packets"] += 1
                stream["bytesOnWire"] += original_length
                stream["payloadBytes"] += len(payload)
                stream["markerPackets"] += payload[1] >> 7
                stream["_sequences"].add(sequence)
                if stream["_rtpTimestamps"] and rtp_timestamp != stream["lastRTPTimestamp"]:
                    stream["_timestampSteps"][(rtp_timestamp - stream["lastRTPTimestamp"]) & 0xFFFFFFFF] += 1
                stream["_rtpTimestamps"].add(rtp_timestamp)
                stream["lastSequence"] = sequence
                stream["lastRTPTimestamp"] = rtp_timestamp
                stream["lastTimestamp"] = timestamp

    for stream in rtp_streams.values():
        sequence_span = ((stream["lastSequence"] - stream["firstSequence"]) & 0xFFFF) + 1
        stream["uniqueSequences"] = len(stream.pop("_sequences"))
        stream["sequenceSpan"] = sequence_span
        stream["missingSequenceNumbersWithinSpan"] = sequence_span - stream["uniqueSequences"]
        stream["uniqueRTPTimestamps"] = len(stream.pop("_rtpTimestamps"))
        stream["commonRTPTimestampSteps"] = dict(stream.pop("_timestampSteps").most_common(10))

    relative_to = markers.get("started", first)
    timeline = [
        {
            "relativeSecond": second - math.floor(relative_to) if relative_to is not None else None,
            **counts,
        }
        for second, counts in sorted(seconds.items())
    ]
    return {
        "file": str(path),
        "packets": len(sizes),
        "bytesOnWire": sum(sizes),
        "firstTimestamp": first,
        "lastTimestamp": last,
        "durationSeconds": (last - first) if first is not None else 0,
        "packetSizeBytes": {
            "minimum": min(sizes) if sizes else None,
            "p50": percentile(sizes, 0.50),
            "p90": percentile(sizes, 0.90),
            "p99": percentile(sizes, 0.99),
            "maximum": max(sizes) if sizes else None,
        },
        "protocolPackets": dict(protocols.most_common()),
        "topBidirectionalFlowsByBytes": dict(flows.most_common(20)),
        "topFlowDetails": {
            name: {**flow_details[name], "durationSeconds": flow_details[name]["lastTimestamp"] - flow_details[name]["firstTimestamp"]}
            for name, _ in flows.most_common(20)
        },
        "topDirectionalFlowsByBytes": dict(directional_flows.most_common(20)),
        "rtpStreams": rtp_streams,
        "rtcpPackets": dict(rtcp_packets.most_common()),
        "rtcpPacketLengths": dict(rtcp_lengths.most_common()),
        "rtcpTrailerBytes": dict(rtcp_trailers.most_common()),
        "recognizedPayloadSignatures": dict(signatures.most_common()),
        "commonPayloadPrefixes": dict(prefixes.most_common(20)),
        "timeline": timeline,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcaps", nargs="+", type=pathlib.Path)
    parser.add_argument("--markers-dir", type=pathlib.Path)
    args = parser.parse_args()
    markers = read_markers(args.markers_dir)
    report = {
        "markers": markers,
        "captures": [summarize(path, markers) for path in args.pcaps],
    }
    json.dump(report, fp=__import__("sys").stdout, indent=2, sort_keys=True)
    print()


if __name__ == "__main__":
    main()
