// Copyright (c) 2016-2017 Kumina, https://kumina.nl/
//
// This file is distributed under a 2-clause BSD license.
// See the LICENSE file for details.

#include <iostream>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

#include "ipv4_ranges.h"
#include "packet_counter.h"

PacketCounter::PacketCounter(const IPv4Ranges* aggregation_ipv4)
    : range_ipv4_(aggregation_ipv4) {}

void PacketCounter::ProcessIPv4Packet(std::uint32_t src, std::uint32_t dst,
                                      std::uint8_t protocol,
                                      std::size_t original_length) {
  packet_size_bytes_all_.Record(original_length);

  // Aggregation on source IPv4 address.
  {
    std::optional<std::size_t> index = range_ipv4_->GetIndexByAddress(src);
    if (index) {
      valid_address_ipv4_[*index] = true;
      packet_size_bytes_ipv4_tx_[*index].Record(original_length);
    }
  }

  // Aggregation on destination IPv4 address.
  {
    std::optional<std::size_t> index = range_ipv4_->GetIndexByAddress(dst);
    if (index) {
      valid_address_ipv4_[*index] = true;
      packet_size_bytes_ipv4_rx_[*index].Record(original_length);
    }
  }
}

void PacketCounter::ProcessUnknownPacket(std::size_t original_length) {
  packet_size_bytes_all_.Record(original_length);
}

void PacketCounter::PrintMetrics(const MetricsLabels& labels,
                                 MetricsPage* output) {
  packet_size_bytes_all_.PrintMetrics("packet_size_bytes_all", labels, output);

  for (auto const &p : valid_address_ipv4_) {
    auto i = p.first;
    // Combine the labels of the packet counter and the per-address
    // histogram.
    std::pair<const MetricsLabels*, std::uint32_t> addr =
      range_ipv4_->GetAddressByIndex(i);
    MetricsLabelsJoiner joiner1(&labels, addr.first);

    // Add the IPv4 address as a label.
    std::stringstream addr_ss;
    addr_ss << (addr.second >> 24) << '.' << (addr.second >> 16 & 0xff) << '.'
            << (addr.second >> 8 & 0xff) << '.' << (addr.second & 0xff);
    std::string addr_str = addr_ss.str();
    MetricsLabel ip("ip", addr_str);
    MetricsLabelsJoiner joiner2(&joiner1, &ip);

    // Print aggregated TX/RX statistics.
    packet_size_bytes_ipv4_tx_[i].PrintMetrics("packet_size_bytes_ipv4_tx",
                                               joiner2, output);
    packet_size_bytes_ipv4_rx_[i].PrintMetrics("packet_size_bytes_ipv4_rx",
                                               joiner2, output);
  }
}
