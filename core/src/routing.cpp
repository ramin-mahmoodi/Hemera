#include "routing.hpp"

#include "dns.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <iterator>
#include <optional>
#include <sstream>
#include <system_error>

namespace aether::core::routing {
namespace {

std::string lowered(std::string_view text) {
    std::string out(text);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char byte) { return static_cast<char>(std::tolower(byte)); });
    return out;
}

bool same_name(std::string_view left, std::string_view right) {
    return lowered(left) == lowered(right);
}

bool ends_with(std::string_view text, std::string_view suffix) {
    return text.size() >= suffix.size() && text.substr(text.size() - suffix.size()) == suffix;
}

std::optional<std::uint16_t> port_number(std::string_view text) {
    text = trim(text);
    std::uint32_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    // A leading '+' parses in Rust and is dropped here; no rule file uses one.
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || value > 65535) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(value);
}

// The address half of a rule, with the network bits kept and the host bits zeroed, which is how
// ipnet reads `10.1.2.3/8` as `10.0.0.0/8`.
std::optional<std::pair<IpAddress, std::uint8_t>> parse_net(std::string_view value) {
    value = trim(value);

    std::string_view address_text = value;
    std::optional<std::uint32_t> prefix;
    if (const auto slash = value.find('/'); slash != std::string_view::npos) {
        address_text = value.substr(0, slash);
        std::uint32_t bits = 0;
        const std::string_view width = trim(value.substr(slash + 1));
        const auto parsed = std::from_chars(width.data(), width.data() + width.size(), bits);
        if (parsed.ec != std::errc{} || parsed.ptr != width.data() + width.size()) return {};
        prefix = bits;
    }

    auto address = parse_address(address_text);
    if (!address) return {};
    const std::uint32_t width = address->v4 ? 32 : 128;
    if (!prefix) prefix = width;
    if (*prefix > width) return {};
    const auto prefix_bits = static_cast<std::uint8_t>(*prefix);

    const std::size_t offset = address->v4 ? 12 : 0;
    for (std::uint32_t byte = 0; byte < width / 8; ++byte) {
        if (prefix_bits >= static_cast<std::uint8_t>((byte + 1) * 8)) continue;
        const std::size_t kept =
            prefix_bits > byte * 8 ? prefix_bits - byte * 8 : 0;
        address->bytes[offset + byte] =
            static_cast<std::uint8_t>(address->bytes[offset + byte] & (0xffu << (8 - kept)));
    }
    return std::pair{*address, prefix_bits};
}

bool inside(const IpAddress& net, std::uint8_t prefix, const IpAddress& address) {
    if (net.v4 != address.v4) return false;
    const std::size_t offset = net.v4 ? 12 : 0;
    const std::size_t width = net.v4 ? 32 : 128;
    for (std::size_t byte = 0; byte < width / 8; ++byte) {
        const std::size_t kept = prefix >= (byte + 1) * 8
                                    ? 8
                                    : (prefix > byte * 8 ? prefix - byte * 8 : 0);
        if (kept == 0) return true;
        if (kept < 8) {
            const auto mask = static_cast<std::uint8_t>(0xffu << (8 - kept));
            return (net.bytes[offset + byte] & mask) == (address.bytes[offset + byte] & mask);
        }
        if (net.bytes[offset + byte] != address.bytes[offset + byte]) return false;
    }
    return true;
}

std::optional<std::string> normalize_domain(std::string_view value) {
    std::string_view text = trim(value);
    while (!text.empty() && text.front() == '*') text.remove_prefix(1);
    while (!text.empty() && text.front() == '.') text.remove_prefix(1);
    while (!text.empty() && text.back() == '.') text.remove_suffix(1);
    if (text.empty()) return std::nullopt;
    return lowered(text);
}

std::optional<std::pair<std::uint16_t, std::uint16_t>> parse_ports(std::string_view value) {
    value = trim(value);
    if (const auto dash = value.find('-'); dash != std::string_view::npos) {
        const auto low = port_number(value.substr(0, dash));
        const auto high = port_number(value.substr(dash + 1));
        if (!low || !high) return std::nullopt;
        return std::pair{std::min(*low, *high), std::max(*low, *high)};
    }
    const auto single = port_number(value);
    if (!single) return std::nullopt;
    return std::pair{*single, *single};
}

void push_list(std::string& target, std::string_view extra) {
    if (trim(extra).empty()) return;
    if (!trim(target).empty()) target.push_back('\n');
    target.append(extra);
}

} // namespace

std::string_view label(Action action) {
    switch (action) {
        case Action::Proxy: return "proxy";
        case Action::Direct: return "direct";
        case Action::Block: return "block";
    }
    return "proxy";
}

bool is_private(const IpAddress& address) {
    const auto& bytes = address.bytes;
    if (address.v4) {
        const std::uint8_t first = bytes[12];
        const std::uint8_t second = bytes[13];
        if (first == 10) return true;
        if (first == 172 && second >= 16 && second <= 31) return true;
        if (first == 192 && second == 168) return true;
        if (first == 127) return true;
        if (first == 169 && second == 254) return true;
        if (first == 255 && second == 255 && bytes[14] == 255 && bytes[15] == 255) return true;
        if (first == 192 && second == 0 && bytes[14] == 2) return true;
        if (first == 198 && second == 51 && bytes[14] == 100) return true;
        if (first == 203 && second == 0 && bytes[14] == 113) return true;
        if (first == 0 && second == 0 && bytes[14] == 0 && bytes[15] == 0) return true;
        return first == 100 && second >= 64 && second < 128;
    }

    const std::uint16_t first = static_cast<std::uint16_t>((bytes[0] << 8) | bytes[1]);
    std::size_t set = 0;
    std::size_t last = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (bytes[i] != 0) {
            ++set;
            last = i;
        }
    }
    if (set == 0) return true;  // ::, which Rust counts as unspecified and so private
    const bool loopback = set == 1 && last == 15 && bytes[15] == 1;
    return loopback || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80;
}

Rule Rule::parse(std::string_view entry) {
    Rule rule;
    entry = trim(entry);
    if (entry.empty() || entry.front() == '#') return rule;

    std::string kind;
    std::string_view value = entry;
    if (const auto colon = entry.find(':'); colon != std::string_view::npos) {
        const std::string_view head = entry.substr(0, colon);
        // `10.0.0.0/8` and `example.com:8080` carry a dot or a slash before their first colon, so
        // they are an address, not a `kind:` prefix.
        if (head.find('.') == std::string_view::npos && head.find('/') == std::string_view::npos) {
            kind = lowered(trim(head));
            value = trim(entry.substr(colon + 1));
        }
    }

    auto set = [&](Kind wanted) {
        rule.kind = wanted;
        return rule;
    };

    if (kind == "domain" || kind == "suffix") {
        const auto name = normalize_domain(value);
        if (!name) return rule;
        rule.text = *name;
        return set(Kind::DomainSuffix);
    }
    if (kind == "full" || kind == "exact") {
        const auto name = normalize_domain(value);
        if (!name) return rule;
        rule.text = *name;
        return set(Kind::DomainFull);
    }
    if (kind == "keyword") {
        if (value.empty()) return rule;
        rule.text = lowered(value);
        return set(Kind::DomainKeyword);
    }
    if (kind == "regexp" || kind == "regex") {
        // A pattern that does not compile drops the rule, as Regex::new(value).ok() does.
        // Google RE2: O(n) regex matching without ReDoS vulnerabilities, matching Rust's regex semantics.
        re2::RE2::Options opt;
        opt.set_log_errors(false);
        auto compiled = std::make_shared<re2::RE2>(re2::StringPiece(value.data(), value.size()), opt);
        if (!compiled->ok()) {
            return rule;
        }
        rule.pattern = std::move(compiled);
        rule.text = std::string(value);
        return set(Kind::DomainRegex);
    }
    if (kind == "ip" || kind == "cidr") {
        const auto net = parse_net(value);
        if (!net) return rule;
        rule.net = net->first;
        rule.prefix = net->second;
        return set(Kind::Net);
    }
    if (kind == "port") {
        const auto ports = parse_ports(value);
        if (!ports) return rule;
        rule.low = ports->first;
        rule.high = ports->second;
        return set(Kind::Ports);
    }
    if (kind == "geoip" || kind == "geosite") {
        if (!same_name(value, "private")) return rule;
        return set(Kind::Private);
    }
    if (!kind.empty()) return rule;

    if (same_name(value, "private")) return set(Kind::Private);
    if (const auto net = parse_net(value); net) {
        rule.net = net->first;
        rule.prefix = net->second;
        return set(Kind::Net);
    }
    if (const auto name = normalize_domain(value); name) {
        rule.text = *name;
        return set(Kind::DomainSuffix);
    }
    return rule;
}

bool Rule::matches(Host host, std::uint16_t port) const {
    const bool domain = std::holds_alternative<std::string_view>(host);
    const std::string_view name = domain ? std::get<std::string_view>(host) : std::string_view{};

    switch (kind) {
        case Kind::None: return false;
        case Kind::Ports: return port >= low && port <= high;
        case Kind::Private:
            if (domain) return same_name(name, "localhost");
            return is_private(std::get<IpAddress>(host));
        case Kind::Net:
            if (domain || !net) return false;
            return inside(*net, prefix, std::get<IpAddress>(host));
        case Kind::DomainSuffix: {
            if (!domain) return false;
            const std::string lowered_name = lowered(name);
            return lowered_name == text || ends_with(lowered_name, "." + text);
        }
        case Kind::DomainFull: return domain && same_name(name, text);
        case Kind::DomainKeyword:
            return domain && lowered(name).find(text) != std::string::npos;
        case Kind::DomainRegex:
            // Matched against the name as it came in, case sensitive, exactly as Rust's regex does.
            return domain && pattern && re2::RE2::PartialMatch(
                re2::StringPiece(name.data(), name.size()), *pattern);
    }
    return false;
}

bool Rule::domain_rule() const {
    return kind == Kind::DomainSuffix || kind == Kind::DomainFull || kind == Kind::DomainKeyword ||
           kind == Kind::DomainRegex;
}

RuleSet RuleSet::parse(std::string_view block, std::string_view direct) {
    RuleSet set;
    set.block_ = parse_list(block);
    set.direct_ = parse_list(direct);
    return set;
}

RuleSet RuleSet::from_env(const Settings& settings, std::vector<std::string>& notes) {
    std::string block(settings.get("AETHER_ROUTE_BLOCK").value_or(std::string_view{}));
    std::string direct(settings.get("AETHER_ROUTE_DIRECT").value_or(std::string_view{}));

    if (const auto path = settings.get("AETHER_ROUTES_FILE")) {
        std::ifstream file(std::string(*path), std::ios::binary);
        if (file) {
            std::stringstream text;
            text << file.rdbuf();
            const auto [file_block, file_direct] = split_sections(text.str());
            push_list(block, file_block);
            push_list(direct, file_direct);
        } else {
            notes.push_back("[-] could not read the routing file " + std::string(*path));
        }
    }

    return parse(block, direct);
}

bool RuleSet::is_empty() const {
    return block_.empty() && direct_.empty();
}

bool RuleSet::has_domain_rules() const {
    return std::any_of(block_.begin(), block_.end(), [](const Rule& rule) {
               return rule.domain_rule();
           }) ||
           std::any_of(direct_.begin(), direct_.end(),
                       [](const Rule& rule) { return rule.domain_rule(); });
}

std::size_t RuleSet::block_count() const {
    return block_.size();
}

std::size_t RuleSet::direct_count() const {
    return direct_.size();
}

Action RuleSet::decide(Host host, std::uint16_t port) const {
    for (const auto& rule : block_) {
        if (rule.matches(host, port)) return Action::Block;
    }
    for (const auto& rule : direct_) {
        if (rule.matches(host, port)) return Action::Direct;
    }
    return Action::Proxy;
}

std::vector<Rule> RuleSet::parse_list(std::string_view raw) {
    std::vector<Rule> rules;
    for (std::size_t at = 0;;) {
        const std::size_t cut = raw.find_first_of("\n,;", at);
        auto rule = Rule::parse(raw.substr(at, cut == std::string_view::npos ? std::string_view::npos
                                                                            : cut - at));
        if (rule.kind != Rule::Kind::None) rules.push_back(std::move(rule));
        if (cut == std::string_view::npos) break;
        at = cut + 1;
    }
    return rules;
}

std::pair<std::string, std::string> RuleSet::split_sections(std::string_view text) {
    std::string block;
    std::string direct;
    std::string* current = nullptr;

    std::size_t at = 0;
    while (at <= text.size()) {
        const std::size_t newline = text.find('\n', at);
        std::string_view line = text.substr(at, newline == std::string_view::npos
                                                   ? std::string_view::npos
                                                   : newline - at);
        at = newline == std::string_view::npos ? text.size() + 1 : newline + 1;

        line = trim(line);
        if (line.empty() || line.front() == '#') continue;

        const std::string lowered_line = lowered(line);
        if (lowered_line == "[block]") {
            current = &block;
            continue;
        }
        if (lowered_line == "[direct]") {
            current = &direct;
            continue;
        }
        if (line.front() == '[') {
            current = nullptr;
            continue;
        }
        if (current != nullptr) {
            current->append(line);
            current->push_back('\n');
        }
    }

    return {block, direct};
}

} // namespace aether::core::routing
