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
#include <algorithm>

#include "ipv4_ranges.h"
#include "packet_counter.h"

#define MAX_NUM_ENTRIES 50000
#define PREFERRED_NUM_ENTRIES 10000

std::map<std::string, Counter> collectGarbage(std::map<std::string, Counter> const &data) {
  std::vector<std::pair<std::string, Counter>> tmp;
  for (auto const &p : data) {
    tmp.push_back(p);
  }

  sort(tmp.begin(), tmp.end(),
    [](std::pair<std::string, Counter> const &a, std::pair<std::string, Counter> const &b) {
      return a.second.Value() > b.second.Value();
    });

  int numEntries = (PREFERRED_NUM_ENTRIES < tmp.size()) ? PREFERRED_NUM_ENTRIES : tmp.size();
  return std::map<std::string, Counter>(tmp.begin(), tmp.begin() + numEntries);
}

PacketCounter::PacketCounter(const IPv4Ranges* aggregation_ipv4) {}

void PacketCounter::ProcessIPPacket(std::string const &src, std::string const &dst,
                                    std::size_t original_length) {
  packet_size_bytes_all_.Record(original_length);
  packet_size_bytes_tx_[src].Record(original_length);
  packet_size_bytes_rx_[dst].Record(original_length);

  if (packet_size_bytes_tx_.size() > MAX_NUM_ENTRIES) {
    std::cout << "GCing on packet_size_bytes_tx_" << std::endl;
    packet_size_bytes_tx_ = collectGarbage(packet_size_bytes_tx_);
  }
  if (packet_size_bytes_rx_.size() > MAX_NUM_ENTRIES) {
    std::cout << "GCing on packet_size_bytes_rx_" << std::endl;
    packet_size_bytes_rx_ = collectGarbage(packet_size_bytes_rx_);
  }
}

void PacketCounter::ProcessUnknownPacket(std::size_t original_length) {
  packet_size_bytes_all_.Record(original_length);
}

void PacketCounter::PrintMetrics(const MetricsLabels& labels,
                                 MetricsPage* output) {
  packet_size_bytes_all_.PrintMetrics("packet_size_bytes_all", labels, output);

  for (auto const &p : packet_size_bytes_tx_) {
    MetricsLabel ip("ip", p.first);
    MetricsLabelsJoiner joiner(&labels, &ip);
    p.second.PrintMetrics("packet_size_bytes_tx", joiner, output);
  }
  for (auto const &p : packet_size_bytes_rx_) {
    MetricsLabel ip("ip", p.first);
    MetricsLabelsJoiner joiner(&labels, &ip);
    p.second.PrintMetrics("packet_size_bytes_rx", joiner, output);
  }
}
