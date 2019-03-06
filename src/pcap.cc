// Copyright (c) 2016-2017 Kumina, https://kumina.nl/
//
// This file is distributed under a 2-clause BSD license.
// See the LICENSE file for details.

#include <pcap/pcap.h>

#include <cassert>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "pcap.h"
#include "raw_packet_processor.h"

std::optional<std::string> Pcap::Activate(const std::string& device,
                                          int port) {
  char errbuf[PCAP_ERRBUF_SIZE];
  std::unique_ptr<pcap_t, PcapDeleter> pcap(
      pcap_create(device.c_str(), errbuf));
  if (!pcap)
    return std::string(errbuf);

  pcap_set_promisc(pcap.get(), false);
  pcap_set_snaplen(pcap.get(), PCAP_SNAPSHOT_SIZE);
  pcap_set_buffer_size(pcap.get(), PCAP_BUFFER_SIZE);

  if (pcap_activate(pcap.get()) != 0)
    return std::string(pcap_geterr(pcap.get()));

  if (port != -1) {
    struct bpf_program fp;
    bpf_u_int32 net, mask;
    char filter_exp[64];
    sprintf(filter_exp, "port %d", port);
    if (pcap_lookupnet(device.c_str(), &net, &mask, errbuf) == -1) {
      return std::string(pcap_geterr(pcap.get()));
    }
    if (pcap_compile(pcap.get(), &fp, filter_exp, 0, net) == -1) {
      return std::string(pcap_geterr(pcap.get()));
    }
    if (pcap_setfilter(pcap.get(), &fp) == -1) {
      return std::string(pcap_geterr(pcap.get()));
    }
  }

  int ret = pcap_setnonblock(pcap.get(), true, errbuf);
  if (ret != 0)
    return std::string(errbuf);

  pcap_ = std::move(pcap);
  return {};
}

void Pcap::Callback_(unsigned char* user, const struct pcap_pkthdr* header,
                     const unsigned char* bytes) {
  RawPacketProcessor* processor = (RawPacketProcessor*)user;
  processor->ProcessPacket({bytes, header->caplen}, header->len);
}

unsigned int Pcap::Dispatch(RawPacketProcessor* processor) {
  assert(pcap_ && "Cannot dispatch before activating.");
  int count = pcap_dispatch(pcap_.get(), 0, &Pcap::Callback_,
                            (unsigned char*)processor);
  assert(count >= 0 && "pcap_dispatch() failed.");
  return count;
}
