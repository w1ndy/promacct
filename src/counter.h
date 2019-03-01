#ifndef COUNTER_H
#define COUNTER_H

#include <array>
#include <cstdint>
#include <string>

#include "metrics_labels.h"
#include "metrics_page.h"

class Counter {
 public:
  Counter() : count_() {}

  void Record(std::uint64_t value) {
    count_ += value;
  }

  // Prints all values stored in the histogram object.
  void PrintMetrics(const std::string& name, const MetricsLabels& labels,
                    MetricsPage* output) const {
    output->PrintMetric(name, labels, count_);
  }

 private:
  std::uint64_t count_;
};

#endif
