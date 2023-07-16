/** -*- c++ -*-
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

#include<openssl/bn.h>
#include<openssl/rsa.h>

#include"tss/tspi.h"

namespace stpm {
#if 0
}
#endif

template<typename T, T*(*New)(), void(*Free)(T*)>
class AutoFree {
 public:
  AutoFree(): resource_(New()) {}
  AutoFree(T* r): resource_(r) {}
  AutoFree(const AutoFree&) = delete;
  AutoFree(const AutoFree&&) = delete;
  AutoFree& operator=(const AutoFree&) = delete;
  AutoFree& operator=(const AutoFree&&) = delete;
  ~AutoFree()
  {
    if (!resource_) {
      return;
    }
    Free(resource_);
    resource_ = nullptr;
  }
  T* get() const
  {
    return resource_;
  }
  T** getp()
  {
    return &resource_;
  }
  T* operator->() const
  {
    return resource_;
  }
  T* release()
  {
    T* ret = resource_;
    resource_ = nullptr;
    return ret;
  }
 private:
  T* resource_;
};

typedef AutoFree<RSA, RSA_new, RSA_free> RSAWrap;
typedef AutoFree<BIGNUM, BN_new, BN_free> BIGNUMWrap;
typedef AutoFree<BN_CTX, BN_CTX_new, BN_CTX_free> BNCTXWrap;

// Exception type for TPM errors, adding helpful troubleshooting information
// in extra().
class TSPIException: public std::runtime_error {
public:
  TSPIException(const std::string& s, int code);
  virtual ~TSPIException() throw() {};
  const std::string& extra() const { return extra_; }
  const int tspi_error;

private:
  static std::string code_to_extra(int);
  static std::string code_to_string(int);

  const std::string extra_;
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


// Convert binary to hex and back.
std::string to_hex(const std::string& s);
std::string to_bin(const std::string& s);

// Like basename(3), but with std::string.
std::string xbasename(const std::string& fullpath);

std::string xgethostname();

// Parse a keyfile into a struct. Does not use the TPM.
Key parse_keyfile(const std::string&);

// Generate a signing key inside the TPM.
// If a PIN is NULL, use the Well Known Secret (20 null bytes unhashed).
Key generate_key(const std::string* srk_pin, const std::string* key_pin,
                 int bits);

// Generate an RSA key in software.
SoftwareKey generate_software_key(int bits);

// Generate a signing key inside the TPM.
// If a PIN is NULL, use the Well Known Secret (20 null bytes unhashed).
Key wrap_key(const std::string* srk_pin, const std::string* key_pin,
             const SoftwareKey& key);

// Sign plain data.
// If a PIN is NULL, use the Well Known Secret (20 null bytes unhashed).
std::string sign(const Key& key, const std::string& data,
                 const std::string* srk_pin,
                 const std::string* key_pin);

// Verify signature.
// This is a software-only operation.
bool verify(const Key& key, const std::string& data,
            const std::string& sig);

// Exfiltrate key
// If a PIN is NULL, use the Well Known Secret (20 null bytes unhashed).
SoftwareKey exfiltrate_key(const Key& key,
                           const std::string* srk_pin,
                           const std::string& owner_password,
                           const std::string* key_pin);

// Return true if key is password protected.
bool auth_required(const std::string* srk_pin, const Key& key);

std::string xctime();

// Read in a whole file.
std::string slurp_file(const std::string& fn);

void do_log(std::ostream* o, const std::string& msg);
std::string xsprintf(const char* fmt, ...);


// This function assumes std::cin is connected to STDIN_FILENO,
// and that std::cout and std::cin are attached to "the terminal".
std::string xgetpass(const std::string& prompt);

void set_policy_secret(TSS_HPOLICY policy, const std::string* pin);
}  // namespace stpm

// Pretty-print keys.
std::ostream& operator<<(std::ostream&, const struct stpm::Key&);
std::ostream& operator<<(std::ostream&, const struct stpm::SoftwareKey&);
#endif
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
