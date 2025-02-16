#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <keystone/keystone.h>
#include <argparse/argparse.hpp>

// Architectures supported by Keystone
static const std::vector<std::string> valid_arch_list =
    {"arm", "arm64", "mips", "x86", "ppc", "sparc", "systemz", "hexagon", "evm"};

// Modes supported by Keystone
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

// Parse architecture using a map from string to ks_arch
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

// Parse mode using a map from string to ks_mode
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
        {"v9", KS_MODE_V9}
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

// Parse syntax using a map from string to bit flags
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

// Assemble a single instruction and print out the resulting bytes
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

// Split a string by `;` and call assemble_and_print for each token
static void process_instructions(
    ks_engine* ks_handle,
    const std::string& instr_text,
    bool no_spaces,
    bool one_line
) {
    std::stringstream instr_stream(instr_text);
    std::string instr_token;
    while (std::getline(instr_stream, instr_token, ';')) {
        // Trim
        while (!instr_token.empty() && isspace(static_cast<unsigned char>(instr_token.front()))) {
            instr_token.erase(instr_token.begin());
        }
        while (!instr_token.empty() && isspace(static_cast<unsigned char>(instr_token.back()))) {
            instr_token.pop_back();
        }
        if (!instr_token.empty()) {
            assemble_and_print(ks_handle, instr_token, no_spaces, one_line);
        }
    }
}

int main(int argc, char** argv) {
    // Create the parser
    argparse::ArgumentParser program("as2b", "0.1.0", argparse::default_arguments::none);

    program.add_argument("-h", "--help")
        .help("print this help message and exit")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("-v", "--version")
        .help("print version information and exit")
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

    program.add_argument("-n", "--no-spaces")
        .help("do not add spaces between output bytes")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("-o", "--one-line")
        .help("print output bytes in one line")
        .default_value(false)
        .implicit_value(true);

    // Capture remaining arguments as instructions
    program.add_argument("instructions")
        .help("assembly instructions (separated by ';' or multiple arguments)")
        .remaining();

    // Parse the command line
    try {
        program.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    // Retrieve values from the parser
    bool help_flag = program.get<bool>("--help");
    bool version_flag = program.get<bool>("--version");
    std::string arch_str = program.get<std::string>("--arch");
    std::string mode_str = program.get<std::string>("--mode");
    std::string syntax_str;
    bool no_spaces_flag = program.get<bool>("--no-spaces");
    bool one_line_flag = program.get<bool>("--one-line");

    // If help is specified, print usage and exit
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

        std::cout << "\nExample:" << std::endl;
        std::cout << "  as2b 'xor rax, rax' ret" << std::endl;
        std::cout << "  as2b -a arm64 -m little 'mov w0, #1; ret'" << std::endl;
        return 0;
    }

    // If version is specified, print version and exit
    if (version_flag) {
        std::cout << "as2b 0.1.0" << std::endl;
        return 0;
    }

    if (program.present("--syntax")) {
        syntax_str = program.get<std::string>("--syntax");
    }

    std::vector<std::string> leftover_args;
    if (program.present("instructions")) {
        leftover_args = program.get<std::vector<std::string>>("instructions");
    }

    // Initialize Keystone
    ks_arch arch_val = parse_arch(arch_str);
    ks_mode mode_val = parse_mode(mode_str);
    int syntax_val = parse_syntax(syntax_str);

    ks_engine* ks_handle = nullptr;
    ks_err err_code = ks_open(arch_val, mode_val, &ks_handle);
    if (err_code != KS_ERR_OK) {
        std::cerr << "failed to initialize Keystone engine: " << ks_strerror(err_code) << std::endl;
        return 1;
    }

    // Set the desired syntax
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

    // If the user provided leftover arguments, assemble them
    // Otherwise, read instructions from stdin until EOF
    if (!leftover_args.empty()) {
        for (const std::string& arg_str : leftover_args) {
            process_instructions(ks_handle, arg_str, no_spaces_flag, one_line_flag);

            if (!no_spaces_flag && &arg_str != &leftover_args.back()) {
                std::cout << " ";
            }
            if (!one_line_flag) {
                std::cout << std::endl;
            }
        }
    } else {
        std::string line_str;
        while (true) {
            // Read a line from stdin until EOF
            if (!std::getline(std::cin, line_str)) {
                break;
            }
            process_instructions(ks_handle, line_str, no_spaces_flag, one_line_flag);

            if (!no_spaces_flag) {
                std::cout << " ";
            }
            if (!one_line_flag) {
                std::cout << std::endl;
            }
        }
    }

    // Print a newline at the end if the output is on one line
    if (one_line_flag) {
        std::cout << std::endl;
    }

    ks_close(ks_handle);
    return 0;
}
