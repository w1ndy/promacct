// Copyright (c) 2016-2017 Kumina, https://kumina.nl/
//
// This file is distributed under a 2-clause BSD license.
// See the LICENSE file for details.

#ifndef PACKET_COUNTER_H
#define PACKET_COUNTER_H

#include <cstdint>
#include <vector>
#include <map>

#include "histogram.h"
#include "parsed_packet_processor.h"
#include "protocol_histogram.h"
#include "counter.h"

class IPv4Ranges;
class MetricsLabels;
class MetricsPage;

// Counts network packets, aggregating them by IPv4 source/destination
// address.
class PacketCounter : public ParsedPacketProcessor {
 public:
  explicit PacketCounter(const IPv4Ranges* aggregation_ipv4);

  // Counts an IP packet.
  void ProcessIPPacket(std::string const &src, std::string const &dst,
                       std::size_t length) override;
  // Counts a network packet of an unknown type.
  void ProcessUnknownPacket(std::size_t length) override;

  // Prints all of the stored histograms to the metrics page output.
  void PrintMetrics(const MetricsLabels& labels, MetricsPage* output);

 private:
  Counter packet_size_bytes_all_;

  std::map<std::string, Counter> packet_size_bytes_tx_;
  std::map<std::string, Counter> packet_size_bytes_rx_;
};

#endif
