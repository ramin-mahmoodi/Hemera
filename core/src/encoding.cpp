#include "encoding.hpp"

#include <array>

namespace aether::core {

namespace {

constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Six bits per character, -1 for anything else. Padding is refused here and handled separately,
// so a table lookup never has to guess what '=' means at this position.
constexpr std::array<int, 256> build_reverse() {
    std::array<int, 256> table{};
    for (int& entry : table) {
        entry = -1;
    }
    for (int i = 0; i < 64; ++i) {
        table[static_cast<unsigned char>(alphabet[i])] = i;
    }
    return table;
}

constexpr auto reverse = build_reverse();

} // namespace

std::string base64_encode(std::span<const uint8_t> data) {
    std::string out;
    out.reserve((data.size() + 2) / 3 * 4);

    size_t i = 0;
    for (; i + 3 <= data.size(); i += 3) {
        const unsigned group = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out += alphabet[(group >> 18) & 0x3F];
        out += alphabet[(group >> 12) & 0x3F];
        out += alphabet[(group >> 6) & 0x3F];
        out += alphabet[group & 0x3F];
    }

    const size_t left = data.size() - i;
    if (left == 1) {
        const unsigned group = data[i] << 16;
        out += alphabet[(group >> 18) & 0x3F];
        out += alphabet[(group >> 12) & 0x3F];
        out += "==";
    } else if (left == 2) {
        const unsigned group = (data[i] << 16) | (data[i + 1] << 8);
        out += alphabet[(group >> 18) & 0x3F];
        out += alphabet[(group >> 12) & 0x3F];
        out += alphabet[(group >> 6) & 0x3F];
        out += '=';
    }

    return out;
}

std::optional<std::vector<uint8_t>> base64_decode(std::string_view text) {
    if (text.empty()) {
        return std::vector<uint8_t>{};
    }

    // Canonical form only, the way the Rust engine decodes: whole 4-character chunks, padding
    // exactly where it belongs, and no bits left over in the final symbol.
    if (text.size() % 4 != 0) {
        return std::nullopt;
    }

    size_t pads = 0;
    while (pads < 2 && text[text.size() - 1 - pads] == '=') {
        ++pads;
    }

    std::vector<uint8_t> out;
    out.reserve(text.size() / 4 * 3);

    for (size_t i = 0; i < text.size(); i += 4) {
        const bool last = (i + 4 == text.size());
        const size_t tail = last ? pads : 0;
        std::array<int, 4> part{};

        for (size_t j = 0; j < 4; ++j) {
            const unsigned char c = static_cast<unsigned char>(text[i + j]);
            if (c == '=') {
                // '=' is only padding, only in the tail of the final chunk.
                if (!last || j + tail < 4) {
                    return std::nullopt;
                }
                part[j] = 0;
                continue;
            }
            part[j] = reverse[c];
            if (part[j] < 0) {
                return std::nullopt;
            }
        }

        const unsigned group = (part[0] << 18) | (part[1] << 12) | (part[2] << 6) | part[3];
        out.push_back(static_cast<uint8_t>(group >> 16));
        if (tail < 2) {
            out.push_back(static_cast<uint8_t>(group >> 8));
        }
        if (tail < 1) {
            out.push_back(static_cast<uint8_t>(group));
        }

        if (tail > 0) {
            const unsigned leftover = tail == 1 ? ((group >> 6) & 0x3) : ((group >> 12) & 0xF);
            if (leftover != 0) {
                return std::nullopt;
            }
        }
    }

    return out;
}

} // namespace aether::core
