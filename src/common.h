/**
 *
 *
 * Header file for all library functions.
 */
#include<string>

namespace stpm {
#if 0
}
#endif

// Key parts in binary.
struct Key {
        std::string exponent;  // Almost certainly 65537.
        std::string modulus;   // 
        std::string blob;      // Blob encrypted by SRK.
};


// Turn trousers error code into useful string.
std::string parseError(int code);

// Convert binary to hex.
std::string to_hex(const std::string&);

// Parse a keyfile into a struct. Does not use the TPM.
Key parse_keyfile(const std::string&);

// Generate a signing key inside the TPM.
Key generate_key();

// Sign plain data.
std::string sign(const Key& key, const std::string& data);

std::string xctime();

}  // namespace stpm

// Pretty-print keys.
std::ostream& operator<<(std::ostream&, struct stpm::Key&);



/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
