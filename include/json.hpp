#pragma once

#include "types.hpp"
#include <string>
#include <vector>
#include <map>
#include <variant>
#include <optional>
#include <string_view>
#include <sstream>
#include <charconv>
#include <cctype>
#include <format>

namespace hemera::json {

class Value;
using Null = std::monostate;
using Array = std::vector<Value>;
using Object = std::map<std::string, Value, std::less<>>;

class Value {
public:
    using Storage = std::variant<Null, bool, double, std::string, Array, Object>;

    Value() : data_(Null{}) {}
    Value(std::nullptr_t) : data_(Null{}) {}
    Value(bool b) : data_(b) {}
    Value(int v) : data_(static_cast<double>(v)) {}
    Value(int64_t v) : data_(static_cast<double>(v)) {}
    Value(uint32_t v) : data_(static_cast<double>(v)) {}
    Value(uint64_t v) : data_(static_cast<double>(v)) {}
    Value(double d) : data_(d) {}
    Value(const char* s) : data_(std::string(s ? s : "")) {}
    Value(std::string s) : data_(std::move(s)) {}
    Value(std::string_view s) : data_(std::string(s)) {}
    Value(Array a) : data_(std::move(a)) {}
    Value(Object o) : data_(std::move(o)) {}

    [[nodiscard]] bool is_null() const noexcept { return std::holds_alternative<Null>(data_); }
    [[nodiscard]] bool is_bool() const noexcept { return std::holds_alternative<bool>(data_); }
    [[nodiscard]] bool is_number() const noexcept { return std::holds_alternative<double>(data_); }
    [[nodiscard]] bool is_string() const noexcept { return std::holds_alternative<std::string>(data_); }
    [[nodiscard]] bool is_array() const noexcept { return std::holds_alternative<Array>(data_); }
    [[nodiscard]] bool is_object() const noexcept { return std::holds_alternative<Object>(data_); }

    [[nodiscard]] bool as_bool(bool default_val = false) const noexcept {
        if (auto p = std::get_if<bool>(&data_)) return *p;
        return default_val;
    }

    [[nodiscard]] int64_t as_int(int64_t default_val = 0) const noexcept {
        if (auto p = std::get_if<double>(&data_)) return static_cast<int64_t>(*p);
        return default_val;
    }

    [[nodiscard]] double as_double(double default_val = 0.0) const noexcept {
        if (auto p = std::get_if<double>(&data_)) return *p;
        return default_val;
    }

    [[nodiscard]] std::string as_string(std::string_view default_val = {}) const {
        if (auto p = std::get_if<std::string>(&data_)) return *p;
        return std::string(default_val);
    }

    [[nodiscard]] const Array& as_array() const {
        static const Array empty{};
        if (auto p = std::get_if<Array>(&data_)) return *p;
        return empty;
    }

    [[nodiscard]] const Object& as_object() const {
        static const Object empty{};
        if (auto p = std::get_if<Object>(&data_)) return *p;
        return empty;
    }

    [[nodiscard]] bool contains(std::string_view key) const noexcept {
        if (auto p = std::get_if<Object>(&data_)) {
            return p->find(key) != p->end();
        }
        return false;
    }

    [[nodiscard]] Value get(std::string_view key, Value default_val = {}) const {
        if (auto p = std::get_if<Object>(&data_)) {
            auto it = p->find(key);
            if (it != p->end()) return it->second;
        }
        return default_val;
    }

    Value& operator[](const std::string& key) {
        if (!std::holds_alternative<Object>(data_)) {
            data_ = Object{};
        }
        return std::get<Object>(data_)[key];
    }

    [[nodiscard]] std::string dump(int indent = -1, int level = 0) const {
        std::string out;
        dump_to(out, indent, level);
        return out;
    }

private:
    Storage data_;

    void dump_to(std::string& out, int indent, int level) const {
        if (std::holds_alternative<Null>(data_)) {
            out += "null";
        } else if (auto b = std::get_if<bool>(&data_)) {
            out += *b ? "true" : "false";
        } else if (auto num = std::get_if<double>(&data_)) {
            if (*num == static_cast<int64_t>(*num)) {
                out += std::to_string(static_cast<int64_t>(*num));
            } else {
                out += std::to_string(*num);
            }
        } else if (auto s = std::get_if<std::string>(&data_)) {
            out += '"';
            for (char c : *s) {
                switch (c) {
                    case '"': out += "\\\""; break;
                    case '\\': out += "\\\\"; break;
                    case '\b': out += "\\b"; break;
                    case '\f': out += "\\f"; break;
                    case '\n': out += "\\n"; break;
                    case '\r': out += "\\r"; break;
                    case '\t': out += "\\t"; break;
                    default:
                        if (static_cast<unsigned char>(c) < 0x20) {
                            out += std::format("\\u{:04x}", static_cast<unsigned int>(static_cast<unsigned char>(c)));
                        } else {
                            out += c;
                        }
                        break;
                }
            }
            out += '"';
        } else if (auto arr = std::get_if<Array>(&data_)) {
            if (arr->empty()) {
                out += "[]";
                return;
            }
            out += '[';
            if (indent >= 0) out += '\n';
            for (size_t i = 0; i < arr->size(); ++i) {
                if (indent >= 0) out.append((level + 1) * indent, ' ');
                (*arr)[i].dump_to(out, indent, level + 1);
                if (i + 1 < arr->size()) out += ',';
                if (indent >= 0) out += '\n';
            }
            if (indent >= 0) out.append(level * indent, ' ');
            out += ']';
        } else if (auto obj = std::get_if<Object>(&data_)) {
            if (obj->empty()) {
                out += "{}";
                return;
            }
            out += '{';
            if (indent >= 0) out += '\n';
            size_t idx = 0;
            for (const auto& [k, v] : *obj) {
                if (indent >= 0) out.append((level + 1) * indent, ' ');
                out += '"';
                out += k;
                out += "\":";
                if (indent >= 0) out += ' ';
                v.dump_to(out, indent, level + 1);
                if (++idx < obj->size()) out += ',';
                if (indent >= 0) out += '\n';
            }
            if (indent >= 0) out.append(level * indent, ' ');
            out += '}';
        }
    }
};

class Parser {
public:
    explicit Parser(std::string_view src) : src_(src), pos_(0) {}

    std::optional<Value> parse() {
        skip_ws();
        if (pos_ >= src_.size()) return std::nullopt;
        auto val = parse_value();
        skip_ws();
        return val;
    }

private:
    std::string_view src_;
    size_t pos_ = 0;

    void skip_ws() {
        while (pos_ < src_.size() && (std::isspace(static_cast<unsigned char>(src_[pos_])) != 0)) {
            ++pos_;
        }
    }

    char peek() const {
        return pos_ < src_.size() ? src_[pos_] : '\0';
    }

    char get() {
        return pos_ < src_.size() ? src_[pos_++] : '\0';
    }

    std::optional<Value> parse_value() {
        skip_ws();
        char c = peek();
        if (c == '"') return parse_string();
        if (c == '{') return parse_object();
        if (c == '[') return parse_array();
        if (c == 't' || c == 'f') return parse_bool();
        if (c == 'n') return parse_null();
        if (c == '-' || (c >= '0' && c <= '9')) return parse_number();
        return std::nullopt;
    }

    std::optional<Value> parse_string() {
        if (get() != '"') return std::nullopt;
        std::string str;
        while (pos_ < src_.size()) {
            char c = get();
            if (c == '"') return Value(str);
            if (c == '\\') {
                if (pos_ >= src_.size()) return std::nullopt;
                char esc = get();
                switch (esc) {
                    case '"': str += '"'; break;
                    case '\\': str += '\\'; break;
                    case '/': str += '/'; break;
                    case 'b': str += '\b'; break;
                    case 'f': str += '\f'; break;
                    case 'n': str += '\n'; break;
                    case 'r': str += '\r'; break;
                    case 't': str += '\t'; break;
                    case 'u': {
                        const auto hex4 = [&]() -> std::optional<uint32_t> {
                            if (pos_ + 4 > src_.size()) return std::nullopt;
                            uint32_t value = 0;
                            for (int i = 0; i < 4; ++i) {
                                const char h = get();
                                value <<= 4;
                                if (h >= '0' && h <= '9') value |= static_cast<uint32_t>(h - '0');
                                else if (h >= 'a' && h <= 'f') value |= static_cast<uint32_t>(h - 'a' + 10);
                                else if (h >= 'A' && h <= 'F') value |= static_cast<uint32_t>(h - 'A' + 10);
                                else return std::nullopt;
                            }
                            return value;
                        };
                        const std::optional first = hex4();
                        if (!first) return std::nullopt;
                        uint32_t codepoint = *first;
                        // serde_json joins a surrogate pair into the codepoint the pair names and
                        // refuses a half with no partner: writing a half out as UTF-8 would leave an
                        // illegal sequence in the string, which the strict walkers downstream reject.
                        if (codepoint >= 0xD800 && codepoint <= 0xDBFF) {
                            if (get() != '\\' || get() != 'u') return std::nullopt;
                            const std::optional low = hex4();
                            if (!low || *low < 0xDC00 || *low > 0xDFFF) return std::nullopt;
                            codepoint = 0x10000u + ((codepoint - 0xD800u) << 10) + (*low - 0xDC00u);
                        } else if (codepoint >= 0xDC00 && codepoint <= 0xDFFF) {
                            return std::nullopt;
                        }
                        if (codepoint < 0x80) {
                            str += static_cast<char>(codepoint);
                        } else if (codepoint < 0x800) {
                            str += static_cast<char>(0xC0 | (codepoint >> 6));
                            str += static_cast<char>(0x80 | (codepoint & 0x3F));
                        } else if (codepoint < 0x10000) {
                            str += static_cast<char>(0xE0 | (codepoint >> 12));
                            str += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
                            str += static_cast<char>(0x80 | (codepoint & 0x3F));
                        } else {
                            str += static_cast<char>(0xF0 | (codepoint >> 18));
                            str += static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F));
                            str += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
                            str += static_cast<char>(0x80 | (codepoint & 0x3F));
                        }
                        break;
                    }
                    default: return std::nullopt;
                }
            } else {
                str += c;
            }
        }
        return std::nullopt;
    }

    std::optional<Value> parse_number() {
        size_t start = pos_;
        if (peek() == '-') get();
        while (pos_ < src_.size() && (std::isdigit(static_cast<unsigned char>(peek())) != 0)) {
            get();
        }
        if (peek() == '.') {
            get();
            while (pos_ < src_.size() && (std::isdigit(static_cast<unsigned char>(peek())) != 0)) {
                get();
            }
        }
        if (peek() == 'e' || peek() == 'E') {
            get();
            if (peek() == '+' || peek() == '-') get();
            while (pos_ < src_.size() && (std::isdigit(static_cast<unsigned char>(peek())) != 0)) {
                get();
            }
        }
        std::string_view num_str = src_.substr(start, pos_ - start);
        double val = 0.0;
        std::from_chars(num_str.data(), num_str.data() + num_str.size(), val);
        return Value(val);
    }

    std::optional<Value> parse_bool() {
        if (src_.substr(pos_, 4) == "true") {
            pos_ += 4;
            return Value(true);
        }
        if (src_.substr(pos_, 5) == "false") {
            pos_ += 5;
            return Value(false);
        }
        return std::nullopt;
    }

    std::optional<Value> parse_null() {
        if (src_.substr(pos_, 4) == "null") {
            pos_ += 4;
            return Value(nullptr);
        }
        return std::nullopt;
    }

    std::optional<Value> parse_array() {
        if (get() != '[') return std::nullopt;
        Array arr;
        skip_ws();
        if (peek() == ']') {
            get();
            return Value(arr);
        }
        while (pos_ < src_.size()) {
            auto elem = parse_value();
            if (!elem) return std::nullopt;
            arr.push_back(std::move(*elem));
            skip_ws();
            char c = get();
            if (c == ']') return Value(arr);
            if (c != ',') return std::nullopt;
        }
        return std::nullopt;
    }

    std::optional<Value> parse_object() {
        if (get() != '{') return std::nullopt;
        Object obj;
        skip_ws();
        if (peek() == '}') {
            get();
            return Value(obj);
        }
        while (pos_ < src_.size()) {
            skip_ws();
            if (peek() != '"') return std::nullopt;
            auto key_val = parse_string();
            if (!key_val) return std::nullopt;
            std::string key = key_val->as_string();
            skip_ws();
            if (get() != ':') return std::nullopt;
            auto val = parse_value();
            if (!val) return std::nullopt;
            obj[std::move(key)] = std::move(*val);
            skip_ws();
            char c = get();
            if (c == '}') return Value(obj);
            if (c != ',') return std::nullopt;
        }
        return std::nullopt;
    }
};

inline std::optional<Value> parse(std::string_view src) {
    Parser p(src);
    return p.parse();
}

// Profile serialization/deserialization
inline Value profile_to_json(const ConnectionProfile& p, bool sanitize_credentials = true) {
    Object o;
    o["protocol"] = std::string(to_string(p.protocol));
    o["scan_mode"] = std::string(to_string(p.scan_mode));
    o["ip_version"] = std::string(to_string(p.ip_version));
    o["quick_reconnect"] = p.quick_reconnect;
    o["masque_http2"] = p.masque_http2;
    o["masque_noize"] = std::string(to_string(p.masque_noize));
    o["wg_noize"] = std::string(to_string(p.wg_noize));
    o["bind_address"] = p.bind_address;
    o["dns"] = p.dns;
    o["zero_trust_team"] = p.zero_trust_team;
    o["zero_trust_auth"] = std::string(to_string(p.zero_trust_auth));

    // Never persist sensitive Zero Trust secrets to disk
    if (sanitize_credentials) {
        o["access_email"] = "";
        o["access_client_id"] = "";
        o["access_client_secret"] = "";
        o["access_token"] = "";
    } else {
        o["access_email"] = p.access_email;
        o["access_client_id"] = p.access_client_id;
        o["access_client_secret"] = p.access_client_secret;
        o["access_token"] = p.access_token;
    }

    o["zero_trust_gateway"] = p.zero_trust_gateway;
    o["route_block"] = p.route_block;
    o["route_direct"] = p.route_direct;
    o["routes_file"] = p.routes_file;
    o["http_proxy"] = p.http_proxy;
    o["upstream"] = p.upstream;
    o["exit_loc"] = p.exit_loc;
    o["system_proxy"] = p.system_proxy;
    o["tun_mode"] = p.tun_mode;
    o["fragment"] = p.fragment;
    o["ech"] = p.ech;
    return Value(std::move(o));
}

inline ConnectionProfile profile_from_json(const Value& val) {
    ConnectionProfile p;
    if (!val.is_object()) return p;

    p.protocol = protocol_from_string(val.get("protocol").as_string("auto"));
    p.scan_mode = scan_mode_from_string(val.get("scan_mode").as_string("balanced"));
    p.ip_version = ip_version_from_string(val.get("ip_version").as_string("v4"));
    p.quick_reconnect = val.get("quick_reconnect").as_bool(true);
    p.masque_http2 = val.get("masque_http2").as_bool(false);
    p.masque_noize = masque_noize_from_string(val.get("masque_noize").as_string("firewall"));
    p.wg_noize = wg_noize_from_string(val.get("wg_noize").as_string("balanced"));
    p.bind_address = val.get("bind_address").as_string(std::string(DEFAULT_BIND_ADDRESS));
    p.dns = val.get("dns").as_string("");
    p.zero_trust_team = val.get("zero_trust_team").as_string("");
    p.zero_trust_auth = zero_trust_auth_from_string(val.get("zero_trust_auth").as_string("email"));
    p.access_email = val.get("access_email").as_string("");
    p.access_client_id = val.get("access_client_id").as_string("");
    p.access_client_secret = val.get("access_client_secret").as_string("");
    p.access_token = val.get("access_token").as_string("");
    p.zero_trust_gateway = val.get("zero_trust_gateway").as_bool(false);
    p.route_block = val.get("route_block").as_string("");
    p.route_direct = val.get("route_direct").as_string("");
    p.routes_file = val.get("routes_file").as_string("");
    p.http_proxy = val.get("http_proxy").as_string("");
    p.upstream = val.get("upstream").as_string("");
    p.exit_loc = val.get("exit_loc").as_string("");
    p.system_proxy = val.get("system_proxy").as_bool(true);
    p.tun_mode = val.get("tun_mode").as_bool(false);
    p.fragment = val.get("fragment").as_bool(false);
    p.ech = val.get("ech").as_bool(false);
    return p;
}

// AppSettings serialization/deserialization
inline Value settings_to_json(const AppSettings& s) {
    Object o;
    o["close_to_tray"] = s.close_to_tray;
    o["autostart"] = s.autostart;
    o["auto_connect"] = s.auto_connect;
    o["theme"] = s.theme;
    o["kill_switch"] = s.kill_switch;
    return Value(std::move(o));
}

inline AppSettings settings_from_json(const Value& val) {
    AppSettings s;
    if (!val.is_object()) return s;
    s.close_to_tray = val.get("close_to_tray").as_bool(false);
    s.autostart = val.get("autostart").as_bool(false);
    s.auto_connect = val.get("auto_connect").as_bool(false);
    s.theme = val.get("theme").as_string("dark");
    s.kill_switch = val.get("kill_switch").as_bool(false);
    return s;
}

} // namespace hemera::json
