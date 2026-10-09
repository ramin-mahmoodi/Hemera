#pragma once

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace hemera::core {

// The core's settings, keyed exactly like the HEMERA_* environment variables the Rust core
// reads. Flags win over variables because apply_cli() writes into a map that already holds
// whatever the environment provided.
struct Settings {
    std::map<std::string, std::string, std::less<>> values;

    [[nodiscard]] const std::string* find(std::string_view key) const;
    [[nodiscard]] std::optional<std::string_view> get(std::string_view key) const {
        const std::string* found = find(key);
        return found == nullptr ? std::nullopt : std::optional<std::string_view>(*found);
    }
    void set(std::string_view key, std::string_view value);
};

// A setting's value without its surrounding spaces.
[[nodiscard]] std::string_view trim(std::string_view text);

// The on/off reading of the Rust core: only 1/true/yes/on, case and space insensitive, turn a
// switch on. `0`, an empty value and stray text all leave it where it was.
[[nodiscard]] bool is_truthy(std::string_view value);

enum class CliOutcome {
    Run,     // every argument was understood; keep going
    Version, // --version: print the version and exit
    Help,    // --help or "help": print usage_text() and exit
    Failure, // unknown option, or a flag whose value is missing
};

// Port of hemera/src/cli.rs: a flag table that writes settings, nothing else. The failure
// reason lands in `error` and already carries the usage block, the way the Rust core does.
CliOutcome apply_cli(const std::vector<std::string>& args, Settings& settings, std::string& error);

// The text `hemera --help` prints. The usage block of hemera/src/cli.rs, minus its tor and
// psiphon sections, so a help screen from this core can be diffed against the shipped binary.
[[nodiscard]] const char* usage_text();

// Every HEMERA_* name the flag table knows, read off the process environment. Flags then layer
// on top through apply_cli(), which is why a flag wins over a variable.
[[nodiscard]] Settings settings_from_environment();

} // namespace hemera::core
