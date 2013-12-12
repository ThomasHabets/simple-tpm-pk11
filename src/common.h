/**
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * Header file for all library functions.
 */
#ifndef __INCLUDE__SIMPLE_TPM_PK11_COMMON_H__
#define __INCLUDE__SIMPLE_TPM_PK11_COMMON_H__

#include<stdexcept>
#include<string>

namespace stpm {
#if 0
}
#endif

// Exception type for TPM errors, adding helpful troubleshooting information
// in extra().
class TSPIException: public std::runtime_error {
public:
  TSPIException(const std::string& s, int code);
  virtual ~TSPIException() throw() {};
  const std::string& extra() const { return extra_; }
  const int tspi_error;

private:
  std::string extra_;
};

// TPM key parts in binary.
struct Key {
  std::string exponent;  // Almost certainly 65537.
  std::string modulus;   //
  std::string blob;      // For HW keys, blob encrypted by SRK.
};

// Software key parts in binary.
struct SoftwareKey {
  std::string exponent;  // Almost certainly 65537.
  std::string modulus;   //
  std::string key;       // The private key.
};


// Turn trousers error code into useful string.
std::string parseError(int code);

// Convert binary to hex.
std::string to_hex(const std::string&);

// Parse a keyfile into a struct. Does not use the TPM.
Key parse_keyfile(const std::string&);

// Generate a signing key inside the TPM.
// If a PIN is zero, use the Well Known Secret (20 null bytes unhashed).
Key generate_key(const std::string* srk_pin, const std::string* key_pin,
                 int bits);

// Generate a signing key inside the TPM.
// If a PIN is zero, use the Well Known Secret (20 null bytes unhashed).
Key wrap_key(const std::string* srk_pin, const std::string* key_pin,
             const SoftwareKey& key);

// Sign plain data.
// If a PIN is zero, use the Well Known Secret (20 null bytes unhashed).
std::string sign(const Key& key, const std::string& data,
                 const std::string* srk_pin,
                 const std::string* key_pin);

// Return true if key is password protected.
bool auth_required(const std::string* srk_pin, const Key& key);

std::string xctime();

void do_log(std::ostream* o, const std::string& msg);
}  // namespace stpm

// Pretty-print keys.
std::ostream& operator<<(std::ostream&, struct stpm::Key&);
#endif
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
