// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
namespace test {
inline unsigned checks{};
inline void require(bool condition, const char *message) {
    ++checks;
    if (!condition)
        throw std::runtime_error(std::string("FAIL: ") + message);
}
template <class F> void rejects(F &&fn, const char *message) {
    ++checks;
    try {
        fn();
    } catch (const std::exception &) {
        return;
    }
    throw std::runtime_error(std::string("FAIL (no exception): ") + message);
}
} // namespace test
void portableTests();
