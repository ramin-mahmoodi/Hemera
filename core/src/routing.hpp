#pragma once

#include "dns.hpp"
#include "settings.hpp"

#include <cstdint>
#include <memory>
#include <re2/re2.h>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace hemera::core::routing {

// Port of routing.rs: the block/direct/proxy decision a connection gets before it leaves, from
// the rule lists the environment and a rules file provide.

enum class Action {
    Proxy,
    Direct,
    Block,
};

[[nodiscard]] std::string_view label(Action action);

// What a rule is looked at against: the name a connection asked for, or the address it goes to.
using Host = std::variant<std::string_view, IpAddress>;

[[nodiscard]] bool is_private(const IpAddress& address);

// One rule, as `domain:`, `keyword:`, `regexp:`, `ip:`, `port:`, `private`, a bare CIDR, or a
// bare name.
class Rule {
public:
    enum class Kind {
        None,
        DomainSuffix,
        DomainFull,
        DomainKeyword,
        DomainRegex,
        Net,
        Ports,
        Private,
    };

    Kind kind = Kind::None;
    std::string text;                              // a name, or a pattern
    std::shared_ptr<const re2::RE2> pattern;       // DomainRegex
    std::optional<IpAddress> net;                  // Net
    std::uint8_t prefix = 0;                       // Net
    std::uint16_t low = 0;                         // Ports
    std::uint16_t high = 0;                        // Ports

    // `entry` as a rule, or Kind::None when it is empty, a comment, or malformed.
    [[nodiscard]] static Rule parse(std::string_view entry);
    [[nodiscard]] bool matches(Host host, std::uint16_t port) const;
    [[nodiscard]] bool domain_rule() const;
};

class RuleSet {
public:
    static RuleSet parse(std::string_view block, std::string_view direct);

    // HEMERA_ROUTE_BLOCK and HEMERA_ROUTE_DIRECT, with the sections of HEMERA_ROUTES_FILE added
    // behind them. A file that cannot be read is reported through `notes` and the rest carries
    // on, which is what the Rust core logs and does.
    [[nodiscard]] static RuleSet from_env(const Settings& settings, std::vector<std::string>& notes);

    [[nodiscard]] bool is_empty() const;
    [[nodiscard]] bool has_domain_rules() const;
    [[nodiscard]] std::size_t block_count() const;
    [[nodiscard]] std::size_t direct_count() const;

    [[nodiscard]] Action decide(Host host, std::uint16_t port) const;

    // A list of rules, split on newlines, commas and semicolons, with comments dropped.
    [[nodiscard]] static std::vector<Rule> parse_list(std::string_view raw);

    // A rules file as its two sections; anything outside [block] and [direct], and any other
    // section, is left out.
    [[nodiscard]] static std::pair<std::string, std::string> split_sections(std::string_view text);

private:
    std::vector<Rule> block_;
    std::vector<Rule> direct_;
};

} // namespace hemera::core::routing
