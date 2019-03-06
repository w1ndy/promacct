// Copyright (c) 2016-2017 Kumina, https://kumina.nl/
//
// This file is distributed under a 2-clause BSD license.
// See the LICENSE file for details.

#ifndef PCAP_H
#define PCAP_H

#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include <cstddef>
#include <memory>
#include <optional>
#include <string>

#define ETHERNET_FRAME_SIZE 14
#define PCAP_SNAPSHOT_SIZE  (ETHERNET_FRAME_SIZE + 40)
#define PCAP_BUFFER_SIZE    (1 << 24)

class RawPacketProcessor;

// Automatic deleter for pcap handles to be used with std::unique_ptr.
class PcapDeleter {
 public:
  void operator()(pcap_t* pcap) {
    pcap_close(pcap);
  }
};

// Network packet capturer based on libpcap.
class Pcap {
 public:
  // Create a pcap handle for a network device and start capturing.
  std::optional<std::string> Activate(const std::string& device,
                                      int port);

  // Read the next batch of packets from the pcap handle and forward its
  // contents over to the raw packet processor.
  unsigned int Dispatch(RawPacketProcessor* processor);

 private:
  std::unique_ptr<pcap_t, PcapDeleter> pcap_;

  // Callback invoked by libpcap.
  static void Callback_(unsigned char* user, const struct pcap_pkthdr* header,
                        const unsigned char* bytes);
};

#endif
