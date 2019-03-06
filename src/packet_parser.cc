// Copyright (c) 2016-2017 Kumina, https://kumina.nl/
//
// This file is distributed under a 2-clause BSD license.
// See the LICENSE file for details.

#include <iostream>
#include <cassert>
#include <cstdint>
#include <string_view>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include "pcap.h"
#include "packet_parser.h"
#include "parsed_packet_processor.h"

u_int16_t ether_packet(const unsigned char *p) {
  struct ether_header *eptr = (struct ether_header*)p;
  return eptr->ether_type;
}

void PacketParser::ProcessPacket(std::basic_string_view<std::uint8_t> bytes,
                                 std::size_t length) {
  char src[INET6_ADDRSTRLEN];
  char dst[INET6_ADDRSTRLEN];

  const u_int16_t type = ether_packet(bytes.data());
  switch (ntohs(type)) {
  case ETHERTYPE_IP:
    inet_ntop(AF_INET, bytes.data() + ETHERNET_FRAME_SIZE + 12, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, bytes.data() + ETHERNET_FRAME_SIZE + 16, dst, INET_ADDRSTRLEN);
    break;
  case ETHERTYPE_IPV6:
    inet_ntop(AF_INET6, bytes.data() + ETHERNET_FRAME_SIZE + 8, src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, bytes.data() + ETHERNET_FRAME_SIZE + 24, dst, INET6_ADDRSTRLEN);
    break;
  default:
    processor_->ProcessUnknownPacket(length);
    return;
  }
  processor_->ProcessIPPacket(src, dst, length);
}
