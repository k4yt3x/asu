#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include <argparse/argparse.hpp>

// Architectures supported by Keystone
static const std::vector<std::string> keystone_arches =
    {"arm", "arm64", "mips", "x86", "ppc", "sparc", "systemz", "hexagon", "evm"};

// Modes supported by Keystone (and mapped to Capstone)
static const std::vector<std::string> keystone_modes = {
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

// Architectures supported by Capstone
static const std::vector<std::string> capstone_arches = {
    "arm",
    "arm64",
    "mips",
    "x86",
    "ppc",
    "sparc",
    "systemz",
    "xcore",
    "m68k",
    "tms320c64x",
    "m680x",
    "evm",
    "mos65xx",
    "wasm",
    "bpf",
    "riscv",
    "sh",
    "tricore"
};

// Modes supported by Capstone
static const std::vector<std::string> capstone_modes = {
    "big",          "16",          "32",          "64",          "thumb",       "mips32",
    "mips64",       "mips32r6",    "v9",          "mclass",      "v8",          "micro",
    "mips3",        "mips2",       "qpx",         "spe",         "booke",       "ps",
    "bpf_extended", "riscv32",     "riscv64",     "riscvc",      "sh2",         "sh2a",
    "sh3",          "sh4",         "sh4a",        "shfpu",       "shdsp",       "tricore_110",
    "tricore_120",  "tricore_130", "tricore_131", "tricore_160", "tricore_161", "tricore_162"
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

// Parse architecture string to Capstone architecture enum
static cs_arch parse_capstone_arch(const std::string& arch_str) {
    static const std::unordered_map<std::string, cs_arch> cs_arch_map = {
        {"arm", CS_ARCH_ARM},
        {"arm64", CS_ARCH_ARM64},
        {"mips", CS_ARCH_MIPS},
        {"x86", CS_ARCH_X86},
        {"ppc", CS_ARCH_PPC},
        {"sparc", CS_ARCH_SPARC},
        {"systemz", CS_ARCH_SYSZ},
        {"xcore", CS_ARCH_XCORE},
        {"m68k", CS_ARCH_M68K},
        {"tms320c64x", CS_ARCH_TMS320C64X},
        {"m680x", CS_ARCH_M680X},
        {"evm", CS_ARCH_EVM},
        {"mos65xx", CS_ARCH_MOS65XX},
        {"wasm", CS_ARCH_WASM},
        {"bpf", CS_ARCH_BPF},
        {"riscv", CS_ARCH_RISCV},
        {"sh", CS_ARCH_SH},
        {"tricore", CS_ARCH_TRICORE},
    };

    auto it = cs_arch_map.find(arch_str);
    return (it != cs_arch_map.end()) ? it->second : CS_ARCH_X86;
}

static cs_mode parse_capstone_mode(const std::string& mode_str) {
    cs_mode mode_val = CS_MODE_LITTLE_ENDIAN;

    if (mode_str.empty()) {
        return mode_val;
    }

    static const std::unordered_map<std::string, cs_mode> cs_mode_map = {
        {"big", CS_MODE_BIG_ENDIAN},
        {"16", CS_MODE_16},
        {"32", CS_MODE_32},
        {"64", CS_MODE_64},
        {"thumb", CS_MODE_THUMB},
        {"mips32", CS_MODE_MIPS32},
        {"mips64", CS_MODE_MIPS64},
        {"mips32r6", CS_MODE_MIPS32R6},
        {"v9", CS_MODE_V9},
        {"mclass", CS_MODE_MCLASS},
        {"v8", CS_MODE_V8},
        {"micro", CS_MODE_MICRO},
        {"mips3", CS_MODE_MIPS3},
        {"mips2", CS_MODE_MIPS2},
        {"qpx", CS_MODE_QPX},
        {"spe", CS_MODE_SPE},
        {"booke", CS_MODE_BOOKE},
        {"ps", CS_MODE_PS},
        {"bpf_extended", CS_MODE_BPF_EXTENDED},
        {"riscv32", CS_MODE_RISCV32},
        {"riscv64", CS_MODE_RISCV64},
        {"riscvc", CS_MODE_RISCVC},
        {"sh2", CS_MODE_SH2},
        {"sh2a", CS_MODE_SH2A},
        {"sh3", CS_MODE_SH3},
        {"sh4", CS_MODE_SH4},
        {"sh4a", CS_MODE_SH4A},
        {"shfpu", CS_MODE_SHFPU},
        {"shdsp", CS_MODE_SHDSP},
        {"tricore_110", CS_MODE_TRICORE_110},
        {"tricore_120", CS_MODE_TRICORE_120},
        {"tricore_130", CS_MODE_TRICORE_130},
        {"tricore_131", CS_MODE_TRICORE_131},
        {"tricore_160", CS_MODE_TRICORE_160},
        {"tricore_161", CS_MODE_TRICORE_161},
        {"tricore_162", CS_MODE_TRICORE_162}
    };

    std::stringstream ss(mode_str);
    std::string token;
    while (std::getline(ss, token, ',')) {
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);
        if (token.empty()) {
            continue;
        }

        auto it = cs_mode_map.find(token);
        if (it != cs_mode_map.end()) {
            mode_val = static_cast<cs_mode>(mode_val | it->second);
        }
    }

    return mode_val;
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

// Assemble the given instruction and print the encoded bytes
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
        // Skip optional "0x" or "\x" prefixes
        size_t pos = 0;
        if (hex_token.substr(0, 2) == "0x" || hex_token.substr(0, 2) == "\\x") {
            pos = 2;
        }

        // Also skip any trailing 'h'
        if (!hex_token.empty() && hex_token.back() == 'h') {
            hex_token.pop_back();
        }

        // Parse each pair of hex chars
        while (pos < hex_token.length()) {
            if (pos + 1 >= hex_token.length()) {
                std::cerr << "incomplete hex byte in '" << hex_token << "'" << std::endl;
                break;
            }

            std::string byte_str = hex_token.substr(pos, 2);
            char* end_ptr;
            uint8_t byte_val = static_cast<uint8_t>(std::strtol(byte_str.c_str(), &end_ptr, 16));

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

// Process the given hex bytes and disassemble them
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
    program.add_argument("instructions").help("assembly instructions or hex bytes").remaining();

    // Parse
    try {
        program.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

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

        std::cout << "\nSupported architectures (assembly):" << std::endl;
        std::string arch_line;
        for (const std::string& arch : keystone_arches) {
            if (arch_line.length() + arch.length() + 1 > 70) {
                std::cout << " " << arch_line << std::endl;
                arch_line = " " + arch;
            } else {
                arch_line += " " + arch;
            }
        }
        if (!arch_line.empty()) {
            std::cout << " " << arch_line << std::endl;
        }

        std::cout << "\nSupported modes (assembly):" << std::endl;
        std::string mode_line;
        for (const std::string& mode : keystone_modes) {
            if (mode_line.length() + mode.length() + 1 > 70) {
                std::cout << " " << mode_line << std::endl;
                mode_line = " " + mode;
            } else {
                mode_line += " " + mode;
            }
        }
        if (!mode_line.empty()) {
            std::cout << " " << mode_line << std::endl;
        }

        std::cout << "\nSupported architectures (disassembly):" << std::endl;
        arch_line.clear();
        for (const std::string& arch : capstone_arches) {
            if (arch_line.length() + arch.length() + 1 > 70) {
                std::cout << " " << arch_line << std::endl;
                arch_line = " " + arch;
            } else {
                arch_line += " " + arch;
            }
        }
        if (!arch_line.empty()) {
            std::cout << " " << arch_line << std::endl;
        }

        std::cout << "\nSupported modes: (disassembly):" << std::endl;
        mode_line.clear();
        for (const std::string& mode : capstone_modes) {
            if (mode_line.length() + mode.length() + 1 > 70) {
                std::cout << " " << mode_line << std::endl;
                mode_line = " " + mode;
            } else {
                mode_line += " " + mode;
            }
        }
        if (!mode_line.empty()) {
            std::cout << " " << mode_line << std::endl;
        }

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

    // Disassembly mode with Capstone
    if (disassemble_flag) {
        // Parse arch/mode for Capstone (no more converting from Keystone).
        cs_arch cs_arch_val = parse_capstone_arch(arch_str);
        cs_mode cs_mode_val = parse_capstone_mode(mode_str);

        // Open Capstone
        csh cs_handle;
        cs_err cs_err_val = cs_open(cs_arch_val, cs_mode_val, &cs_handle);
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

    // Assembly mode with Keystone
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

            // If not the last one, and user wants spaces, put a space
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
