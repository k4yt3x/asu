#include <cstring>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include <argparse/argparse.hpp>

// Architectures supported by Keystone (and mapped to Capstone)
static const std::vector<std::string> valid_arch_list =
    {"arm", "arm64", "mips", "x86", "ppc", "sparc", "systemz", "hexagon", "evm"};

// Modes supported by Keystone (and mapped to Capstone)
static const std::vector<std::string> valid_mode_list = {
    "big",
    "arm",
    "thumb",
    "v8",
    "micro",
    "mips3",
    "mips32",
    "mips64",
    "mips32r6",
    "16",
    "32",
    "64",
    "ppc32",
    "ppc64",
    "qpx",
    "sparc32",
    "sparc64",
    "v9"
};

// Parse architecture string to Keystone architecture enum
static ks_arch parse_arch(const std::string& arch_str) {
    static const std::unordered_map<std::string, ks_arch> arch_map = {
        {"arm", KS_ARCH_ARM},
        {"arm64", KS_ARCH_ARM64},
        {"mips", KS_ARCH_MIPS},
        {"x86", KS_ARCH_X86},
        {"ppc", KS_ARCH_PPC},
        {"sparc", KS_ARCH_SPARC},
        {"systemz", KS_ARCH_SYSTEMZ},
        {"hexagon", KS_ARCH_HEXAGON},
        {"evm", KS_ARCH_EVM}
    };

    if (arch_str.empty()) {
        return KS_ARCH_X86;
    }

    auto it = arch_map.find(arch_str);
    if (it != arch_map.end()) {
        return it->second;
    }
    return KS_ARCH_X86;
}

// Parse mode string to Keystone mode bitmask
static ks_mode parse_mode(const std::string& mode_str) {
    static const std::unordered_map<std::string, ks_mode> mode_map = {
        {"little", KS_MODE_LITTLE_ENDIAN},
        {"big", KS_MODE_BIG_ENDIAN},
        {"arm", KS_MODE_ARM},
        {"thumb", KS_MODE_THUMB},
        {"v8", KS_MODE_V8},
        {"micro", KS_MODE_MICRO},
        {"mips3", KS_MODE_MIPS3},
        {"mips32", KS_MODE_MIPS32},
        {"mips64", KS_MODE_MIPS64},
        {"mips32r6", KS_MODE_MIPS32R6},
        {"16", KS_MODE_16},
        {"32", KS_MODE_32},
        {"64", KS_MODE_64},
        {"ppc32", KS_MODE_PPC32},
        {"ppc64", KS_MODE_PPC64},
        {"qpx", KS_MODE_QPX},
        {"sparc32", KS_MODE_SPARC32},
        {"sparc64", KS_MODE_SPARC64},
        {"v9", KS_MODE_V9},
    };

    ks_mode mode_val = KS_MODE_LITTLE_ENDIAN;
    if (mode_str.empty()) {
        return mode_val;
    }

    std::stringstream ss(mode_str);
    std::string token;
    while (std::getline(ss, token, ',')) {
        // Trim
        while (!token.empty() && isspace((unsigned char)token.front())) {
            token.erase(token.begin());
        }
        while (!token.empty() && isspace((unsigned char)token.back())) {
            token.pop_back();
        }
        if (token.empty()) {
            continue;
        }

        auto it = mode_map.find(token);
        if (it != mode_map.end()) {
            mode_val = static_cast<ks_mode>(
                static_cast<unsigned>(mode_val) | static_cast<unsigned>(it->second)
            );
        }
    }
    return mode_val;
}

// Convert Keystone architecture to Capstone architecture
static std::optional<cs_arch> ks_to_cs_arch(ks_arch karch) {
    static const std::unordered_map<ks_arch, cs_arch> k2c_arch_map = {
        {KS_ARCH_X86, CS_ARCH_X86},
        {KS_ARCH_ARM, CS_ARCH_ARM},
        {KS_ARCH_ARM64, CS_ARCH_ARM64},
        {KS_ARCH_MIPS, CS_ARCH_MIPS},
        {KS_ARCH_PPC, CS_ARCH_PPC},
        {KS_ARCH_SPARC, CS_ARCH_SPARC},
        {KS_ARCH_SYSTEMZ, CS_ARCH_SYSZ},
        // Hexagon does not exist in Capstone
        // EVM does not exist in Capstone
    };

    auto it = k2c_arch_map.find(karch);
    if (it != k2c_arch_map.end()) {
        return it->second;
    }
    // Default to x86 if architecture not found
    return CS_ARCH_X86;
}

// Convert Keystone mode to Capstone mode
static cs_mode ks_to_cs_mode(ks_arch arch, ks_mode kmode) {
    // Default to Little Endian
    cs_mode result = static_cast<cs_mode>(0);

    // Endianness
    if (kmode & KS_MODE_BIG_ENDIAN) {
        result = static_cast<cs_mode>(result | CS_MODE_BIG_ENDIAN);
    } else {
        result = static_cast<cs_mode>(result | CS_MODE_LITTLE_ENDIAN);
    }

    // For x86
    if (arch == KS_ARCH_X86) {
        if (kmode & KS_MODE_16) {
            result = static_cast<cs_mode>(result | CS_MODE_16);
        } else if (kmode & KS_MODE_32) {
            result = static_cast<cs_mode>(result | CS_MODE_32);
        } else if (kmode & KS_MODE_64) {
            result = static_cast<cs_mode>(result | CS_MODE_64);
        }
    }

    // For ARM / ARM64
    if (arch == KS_ARCH_ARM || arch == KS_ARCH_ARM64) {
        if (kmode & KS_MODE_THUMB) {
            result = static_cast<cs_mode>(result | CS_MODE_THUMB);
        }
    }

    // For MIPS
    if (arch == KS_ARCH_MIPS) {
        if (kmode & KS_MODE_MIPS32R6) {
            result = static_cast<cs_mode>(result | CS_MODE_MIPS32R6);
        }
    }

    // For SPARC
    if (arch == KS_ARCH_SPARC) {
        if (kmode & KS_MODE_V9) {
            result = static_cast<cs_mode>(result | CS_MODE_V9);
        }
    }

    return result;
}

// Parse syntax string to Keystone syntax bitmask
static int parse_syntax(const std::string& syntax_str) {
    static const std::unordered_map<std::string, int> syntax_map = {
        {"intel", KS_OPT_SYNTAX_INTEL},
        {"att", KS_OPT_SYNTAX_ATT},
        {"nasm", KS_OPT_SYNTAX_NASM},
        {"masm", KS_OPT_SYNTAX_MASM},
        {"gas", KS_OPT_SYNTAX_GAS},
        {"radix16", KS_OPT_SYNTAX_RADIX16},
    };

    if (syntax_str.empty()) {
        return 0;
    }

    int syntax_val = 0;
    std::stringstream ss(syntax_str);
    std::string token;
    while (std::getline(ss, token, ',')) {
        // Trim
        while (!token.empty() && isspace(static_cast<unsigned char>(token.front()))) {
            token.erase(token.begin());
        }
        while (!token.empty() && isspace(static_cast<unsigned char>(token.back()))) {
            token.pop_back();
        }
        if (token.empty()) {
            continue;
        }

        auto it = syntax_map.find(token);
        if (it != syntax_map.end()) {
            syntax_val |= it->second;
        }
    }
    return syntax_val;
}

// Assemble and print the given instruction
static void
assemble_and_print(ks_engine* ks_handle, const std::string& instr, bool no_spaces, bool one_line) {
    if (instr.empty()) {
        return;
    }

    unsigned char* encoded_bytes = nullptr;
    size_t encoded_size = 0;
    size_t instr_count = 0;

    ks_err err_code = static_cast<ks_err>(
        ks_asm(ks_handle, instr.c_str(), 0, &encoded_bytes, &encoded_size, &instr_count)
    );
    if (err_code != KS_ERR_OK) {
        std::cerr << "failed to assemble \"" << instr << "\": " << ks_strerror(err_code)
                  << std::endl;
        return;
    }

    // Print each byte in hex
    for (size_t i = 0; i < encoded_size; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned>(encoded_bytes[i]);
        if (!no_spaces && i + 1 < encoded_size) {
            std::cout << ' ';
        }
    }
    std::cout << std::dec;

    ks_free(encoded_bytes);
}

// Parse a string of hex bytes into a vector of bytes
static std::vector<uint8_t> parse_hex_bytes(const std::string& hex_str) {
    std::vector<uint8_t> bytes;
    std::string hex_token;
    std::istringstream hex_stream(hex_str);

    while (hex_stream >> hex_token) {
        // Skip optional "0x" or "h" prefixes
        size_t pos = 0;
        if (hex_token.substr(0, 2) == "0x") {
            pos = 2;
        } else if (hex_token.substr(0, 2) == "\\x") {
            pos = 2;
        }

        // Also skip any "h" suffix
        if (!hex_token.empty() && hex_token.back() == 'h') {
            hex_token.pop_back();
        }

        // Parse each pair of hex chars
        while (pos < hex_token.length()) {
            // Need at least 2 chars
            if (pos + 1 >= hex_token.length()) {
                std::cerr << "incomplete hex byte in '" << hex_token << "'" << std::endl;
                break;
            }

            // Convert hex chars to byte value
            std::string byte_str = hex_token.substr(pos, 2);
            char* end_ptr;
            uint8_t byte_val = static_cast<uint8_t>(std::strtol(byte_str.c_str(), &end_ptr, 16));

            // Check if the conversion succeeded
            if (end_ptr != byte_str.c_str() + 2) {
                std::cerr << "invalid hex byte '" << byte_str << "'" << std::endl;
                break;
            }

            bytes.push_back(byte_val);
            pos += 2;
        }
    }

    return bytes;
}

// Disassemble and print the given bytes
static void disassemble_and_print(csh cs_handle, const std::vector<uint8_t>& code, bool no_offset) {
    cs_insn* insn = nullptr;
    // Start address at 0 for display
    uint64_t address = 0;
    size_t count = cs_disasm(cs_handle, code.data(), code.size(), address, 0, &insn);
    if (count == 0) {
        std::cerr << "failed to disassemble the given bytes" << std::endl;
        return;
    }

    for (size_t i = 0; i < count; i++) {
        if (!no_offset) {
            std::cout << "0x" << std::hex << insn[i].address << ": ";
        }
        std::cout << insn[i].mnemonic << " " << insn[i].op_str << std::dec << std::endl;
    }

    cs_free(insn, count);
}

// Process a line of instructions (disassembly)
static void process_bytes(csh cs_handle, const std::string& hex_text, bool no_offset) {
    // We parse the entire line as one set of bytes
    std::vector<uint8_t> bytes = parse_hex_bytes(hex_text);
    if (!bytes.empty()) {
        disassemble_and_print(cs_handle, bytes, no_offset);
    }
}

int main(int argc, char** argv) {
    // Create the parser, rename program to "asu"
    argparse::ArgumentParser program("asu", "0.1.0", argparse::default_arguments::none);

    program.add_argument("-h", "--help")
        .help("print this help message and exit")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("-v", "--version")
        .help("print version information and exit")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("-d", "--disassemble")
        .help("disassemble input bytes (default is assemble)")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("-a", "--arch")
        .help("select architecture (x86, arm, arm64, mips, etc.)")
        .default_value(std::string("x86"));

    program.add_argument("-m", "--mode")
        .help("select mode, comma-separated (e.g. 64,big,thumb)")
        .default_value(std::string("64"));

    program.add_argument("-s", "--syntax")
        .help("select syntax (intel, att, nasm, masm, gas, radix16)");

    program.add_argument("-p", "--no-spaces")
        .help("do not add spaces between output bytes (assembly)")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("-l", "--one-line")
        .help("print output bytes in one line (assembly)")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("-o", "--no-offset")
        .help("do not print the offset of the instruction")
        .default_value(false)
        .implicit_value(true);

    // Capture remaining arguments
    program.add_argument("instructions")
        .help("assembly instructions or hex bytes (depending on mode); multiple arguments OK")
        .remaining();

    // Parse
    try {
        program.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    // Retrieve values
    bool help_flag = program.get<bool>("--help");
    bool version_flag = program.get<bool>("--version");
    bool disassemble_flag = program.get<bool>("--disassemble");
    std::string arch_str = program.get<std::string>("--arch");
    std::string mode_str = program.get<std::string>("--mode");
    std::string syntax_str;
    bool no_spaces_flag = program.get<bool>("--no-spaces");
    bool one_line_flag = program.get<bool>("--one-line");
    bool no_offset_flag = program.get<bool>("--no-offset");

    if (help_flag) {
        std::cout << program;

        std::cout << "\nSupported architectures:" << std::endl;
        for (const std::string& arch : valid_arch_list) {
            std::cout << " " << arch;
        }
        std::cout << "\n\nSupported modes:" << std::endl;
        for (const std::string& mode : valid_mode_list) {
            std::cout << " " << mode;
        }
        std::cout << std::endl;

        std::cout << "\nExample (assembly):" << std::endl;
        std::cout << "  asu 'xor rax, rax' ret" << std::endl;
        std::cout << "  asu -a arm64 -m little -pl 'mov w0, #1; ret'" << std::endl;

        std::cout << "\nExample (disassembly):" << std::endl;
        std::cout << "  asu -d 4831c0c3" << std::endl;
        std::cout << "  asu -a arm64 -m little -d 20008052c0035fd6" << std::endl;
        return 0;
    }

    if (version_flag) {
        std::cout << "asu 0.1.0" << std::endl;
        return 0;
    }

    if (program.present("--syntax")) {
        syntax_str = program.get<std::string>("--syntax");
    }

    // Get instructions (which might be assembly or hex bytes)
    std::vector<std::string> leftover_args;
    if (program.present("instructions")) {
        leftover_args = program.get<std::vector<std::string>>("instructions");
    }

    // Disassembly mode
    if (disassemble_flag) {
        // Convert ks -> cs
        ks_arch ks_arch_val = parse_arch(arch_str);
        ks_mode ks_mode_val = parse_mode(mode_str);
        std::optional<cs_arch> cs_arch_val = ks_to_cs_arch(ks_arch_val);
        cs_mode cs_mode_val = ks_to_cs_mode(ks_arch_val, ks_mode_val);

        if (!cs_arch_val.has_value()) {
            std::cerr << "unsupported architecture: " << arch_str << std::endl;
            return 1;
        }

        // Open Capstone
        csh cs_handle;
        cs_err cs_err_val = cs_open(cs_arch_val.value(), cs_mode_val, &cs_handle);
        if (cs_err_val != CS_ERR_OK) {
            std::cerr << "failed to initialize Capstone: " << cs_strerror(cs_err_val) << std::endl;
            return 1;
        }

        // If x86, apply syntax as needed
        if (cs_arch_val == CS_ARCH_X86 && !syntax_str.empty()) {
            if (syntax_str.find("att") != std::string::npos) {
                cs_option(cs_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
            } else {
                cs_option(cs_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
            }
        }

        // Disassemble leftover_args as hex
        if (!leftover_args.empty()) {
            for (auto& arg_str : leftover_args) {
                process_bytes(cs_handle, arg_str, no_offset_flag);
            }
        } else {
            // Or read from stdin
            std::string line_str;
            while (true) {
                if (!std::getline(std::cin, line_str)) {
                    break;
                }
                process_bytes(cs_handle, line_str, no_offset_flag);
            }
        }

        cs_close(&cs_handle);
        return 0;
    }

    // Assembly mode
    ks_arch arch_val = parse_arch(arch_str);
    ks_mode mode_val = parse_mode(mode_str);
    int syntax_val = parse_syntax(syntax_str);

    // Initialize Keystone
    ks_engine* ks_handle = nullptr;
    ks_err err_code = ks_open(arch_val, mode_val, &ks_handle);
    if (err_code != KS_ERR_OK) {
        std::cerr << "failed to initialize Keystone engine: " << ks_strerror(err_code) << std::endl;
        return 1;
    }

    // Set the desired syntax (if any)
    if (syntax_val != 0) {
        err_code = ks_option(ks_handle, KS_OPT_SYNTAX, syntax_val);
        if (err_code == KS_ERR_OPT_INVALID) {
            std::cerr << "syntax '" << syntax_str << "' is not supported for this architecture"
                      << std::endl;
            ks_close(ks_handle);
            return 1;
        } else if (err_code != KS_ERR_OK) {
            std::cerr << "failed to set syntax option: " << ks_strerror(err_code) << std::endl;
            ks_close(ks_handle);
            return 1;
        }
    }

    // If leftover_args exist, assemble them
    if (!leftover_args.empty()) {
        for (const std::string& arg_str : leftover_args) {
            assemble_and_print(ks_handle, arg_str, no_spaces_flag, one_line_flag);

            if (!no_spaces_flag && &arg_str != &leftover_args.back()) {
                std::cout << " ";
            }
            if (!one_line_flag) {
                std::cout << std::endl;
            }
        }
    } else {
        // Otherwise, read from stdin until EOF
        std::string line_str;
        while (true) {
            if (!std::getline(std::cin, line_str)) {
                break;
            }
            assemble_and_print(ks_handle, line_str, no_spaces_flag, one_line_flag);

            if (!no_spaces_flag) {
                std::cout << " ";
            }
            if (!one_line_flag) {
                std::cout << std::endl;
            }
        }
    }

    // Print a newline at the end if user wants all on one line
    if (one_line_flag) {
        std::cout << std::endl;
    }

    ks_close(ks_handle);
    return 0;
}
