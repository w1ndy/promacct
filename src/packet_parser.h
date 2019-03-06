// Copyright (c) 2016-2017 Kumina, https://kumina.nl/
//
// This file is distributed under a 2-clause BSD license.
// See the LICENSE file for details.

#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <string_view>

#include "raw_packet_processor.h"

class ParsedPacketProcessor;

// Adapter for parsing Ethernet packets.
//
// The Pcap class invokes ProcessPacket(), providing it access to the
// raw packet data. This class attempts to extract the IPv4 source and
// destination addresses and invokes the methods of the
// ParsedPacketProcessor.
class PacketParser : public RawPacketProcessor {
 public:
  explicit PacketParser(ParsedPacketProcessor* processor)
      : processor_(processor) {
  }

  // Parses raw packets.
  void ProcessPacket(std::basic_string_view<std::uint8_t> bytes,
                     std::size_t length) override;

 private:
  ParsedPacketProcessor* const processor_;
};

#endif
