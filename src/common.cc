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
#include<cstdarg>
#include<cstdio>
#include<cstring>
#include<fstream>
#include<functional>
#include<iomanip>
#include<iostream>
#include<libgen.h>
#include<map>
#include<sstream>
#include<stdexcept>
#include<string>
#include<termios.h>
#include<unistd.h>
#include<vector>

#include"openssl/err.h"
#include"openssl/rand.h"
#include"openssl/rsa.h"
#include"openssl/x509.h"

#include"tss/tspi.h"
#include"trousers/trousers.h"

#include"common.h"
#include"tspiwrap.h"
#include"internal.h"

std::ostream&
operator<<(std::ostream& o, const struct stpm::Key& key)
{
  o << "mod=" << stpm::to_hex(key.modulus)
    << ",exp=" << stpm::to_hex(key.exponent)
    << ",blob=" << stpm::to_hex(key.blob);
  return o;
}

std::ostream&
operator<<(std::ostream& o, const struct stpm::SoftwareKey& key)
{
  o << "mod=" << stpm::to_hex(key.modulus)
    << ",exp=" << stpm::to_hex(key.exponent)
    << ",key=" << stpm::to_hex(key.key);
  return o;
}

BEGIN_NAMESPACE(stpm);
const std::string random_device = "/dev/urandom";
const int num_random_bytes = 32; // 256 bits.
const char* env_log_stderr = "SIMPLE_TPM_PK11_LOG_STDERR";
const TSS_UUID srk_uuid = TSS_UUID_SRK;

std::string
xgetpass(const std::string& prompt)
{
  const int fd = STDIN_FILENO;
  std::cout << prompt << ": " << std::flush;
  std::string line;
  if (!isatty(fd)) {
    getline(std::cin, line);
  } else {
    struct termios old;
    if (tcgetattr(fd, &old)) {
      throw std::runtime_error(std::string("tcgetattr(stdin): ") + strerror(errno));
    }

    struct termios ti = old;
    ti.c_lflag &= ~ECHO;
    if (tcsetattr(fd, TCSAFLUSH, &ti)) {
      throw std::runtime_error(std::string("tcsetattr(stdin, TCSAFLUSH, no echo): ") + strerror(errno));
    }
    getline(std::cin, line);
    if (tcsetattr(fd, TCSAFLUSH, &old)) {
      throw std::runtime_error(std::string("tcsetattr(stdin, TCSAFLUSH, old): ") + strerror(errno));
    }
  }
  std::cout << std::endl;
  return line;
}

// Wrap Tspi_* calls, checking return value and throwing exception.
// TODO: Adding debug logging.
TSS_RESULT
tscall(const std::string& name, std::function<TSS_RESULT()> func)
{
  TSS_RESULT res;
  if (TSS_SUCCESS != (res = func())) {
    throw TSPIException(name, res);
  }
  return res;
}

TSPIException::TSPIException(const std::string& func, int code)
    :std::runtime_error(func + ": " + code_to_string(code)),
     tspi_error(code),
     extra_(code_to_extra(code))
{ }

// Turn trousers error code into useful string.
std::string
TSPIException::code_to_string(int code)
{
  const std::string layer{Trspi_Error_Layer(code)};
  const std::string err{Trspi_Error_String(code)};

  std::stringstream ss;
  ss << "Code=0x"
     << std::setw(8) << std::setbase(16) << std::setfill('0') << code
     << ": " << layer
     << ": " << err;
  return ss.str();
}

std::string
TSPIException::code_to_extra(int code)
{
  switch (code) {
  case TPM_E_INVALID_KEYHANDLE:
    return "Likely problem:\n"
      "  If this happened while trying to read the public SRK, then your TPM is not\n"
      "  configured to allow that. If it happens on any other key then it's probably\n"
      "  a bug in simple-tpm-pk11.\n"
      "Possible solution:\n"
      "  Allow reading public SRK with tpm_restrictsrk -a.";
  case TPM_E_AUTHFAIL:
    return "Likely problem:\n"
      "  Either the SRK password or the key password is incorrect.\n"
      "  The Well Known Secret (20 nulls unhashed) is not the same as the password \"\".\n"
      "Possible solution:\n"
      "  The SRK password can (and arguable should) be set to the Well Known Secret using:\n"
      "    tpm_changeownerauth -s -r\n"
      "  Alternatively the SRK password can be given with -s to stpm-keygen/stpm-sign and\n"
      "  with srk_pin in the configuration file for the PKCS#11 module.";
  case TSS_LAYER_TSP | TSS_E_COMM_FAILURE:
    return "Likely problem:\n"
      "  The tscd daemon is not running and listening on TCP port 30003, or there\n"
      "  is a firewall preventing connections to it.\n"
      "Possible solution:\n"
      "  Make sure trousers is started (/etc/init.d/trousers start) correctly, and\n"
      "  and check any logs for why it might not be coming up correctly.\n"
      "  It could fail to start because it's not finding a device /dev/tpm*.";
  case TSS_E_PS_KEY_NOTFOUND:
    return "Likely problem:\n"
      "  The TPM chip is not active. Use tpm_getpubek to see if its error message\n"
      "  confirms this.\n"
      "Possible solution:\n"
      "  Power off the machine, power it back on, go into BIOS, and make sure the\n"
      "  TPM chip / security chip is \"Active\".";
  }
  return "";
}

std::string
xrandom(int bytes)
{
  std::vector<char> buf(bytes);
  std::ifstream f;
  f.rdbuf()->pubsetbuf(nullptr, 0);
  f.open(random_device, std::ios::binary);
  if (!f.good()) {
    throw std::runtime_error("Failed to open " + random_device);
  }
  f.read(&buf[0], buf.size());
  if (f.fail() || f.eof()) {
    throw std::runtime_error("EOF in " + random_device);
  }
  if (static_cast<size_t>(f.gcount()) != buf.size()) {
    throw std::runtime_error("Short full read from " + random_device);
  }
  return std::string(buf.begin(), buf.end());
}

std::string
bn2string(const BIGNUM* bn)
{
  std::vector<unsigned char> buf(BN_num_bytes(bn));
  unsigned int size;
  if (0 >= (size = BN_bn2bin(bn, &buf[0]))) {
    throw std::runtime_error("Broken BIGNUM sent to BN_bn2bin.");
  }
  return std::string(buf.begin(), buf.end());
}

BIGNUM*
string2bn(const std::string& s)
{
  BIGNUM* ret = BN_new();
  if (!BN_bin2bn(reinterpret_cast<const unsigned char*>(s.data()), s.size(), ret)) {
    throw std::runtime_error("Broken BIGNUM sent to BN_bin2bn.");
  }
  return ret;
}

std::string
xctime()
{
  time_t t;
  time(&t);
  char buf[128] = {0};
  ctime_r(&t, buf);
  while (strlen(buf) && buf[strlen(buf)-1] == '\n') {
    buf[strlen(buf)-1] = 0;
  }
  return buf;
}

std::string
xsprintf(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);

  va_list va2;
  va_copy(va2, args);

  size_t s = vsnprintf(NULL, 0, fmt, args) + 1;
  va_end(args);

  std::vector<char> buf(s);
  vsnprintf(&buf[0], s, fmt, va2);
  va_end(va2);

  return std::string(buf.begin(), buf.end());
}

bool
log_stderr()
{
  const char *doit{getenv(env_log_stderr)};
  return !!doit;
}

void
do_log(std::ostream* o, const std::string& msg)
{
  *o << msg << std::endl;
  if (log_stderr()) {
    std::cerr << msg << std::endl;
  }
}

int
keysize_flag(int bits) {
  switch (bits) {
  case 512:
    return TSS_KEY_SIZE_512;
  case 1024:
    return TSS_KEY_SIZE_1024;
  case 2048:
    return TSS_KEY_SIZE_2048;
  case 4096:
    return TSS_KEY_SIZE_4096;
  case 8192:
    return TSS_KEY_SIZE_8192;
  case 16384:
    return TSS_KEY_SIZE_16384;
  }
  throw std::runtime_error("Unknown key size: " + std::to_string(bits) + "bit");
}

SoftwareKey
generate_software_key(int bits)
{
  const std::string entropy = xrandom(num_random_bytes);
  RAND_seed(entropy.data(), entropy.size());
  if (!RAND_status()) {
    throw std::runtime_error("OpenSSL PRNG wants more entropy");
  }

  RSA *rsa = RSA_new();
  BIGNUM *f4 = BN_new();
  BN_set_word(f4, RSA_F4);
  if (!RSA_generate_key_ex(rsa, bits, f4, NULL)) {
    throw std::runtime_error("RSA_generate_key_ex failed");
  }
  SoftwareKey swkey;
  swkey.modulus = bn2string(rsa->n);
  swkey.key = bn2string(rsa->p);
  swkey.exponent = bn2string(rsa->e);
  return swkey;
}

Key
wrap_key(const std::string* srk_pin, const std::string* key_pin,
         const SoftwareKey& swkey)
{
  TPMStuff stuff{srk_pin};

  // === Set up key object ===
  int init_flags =
    TSS_KEY_TYPE_SIGNING
    | keysize_flag(swkey.modulus.size() * 8)
    | TSS_KEY_VOLATILE
    | TSS_KEY_NO_AUTHORIZATION
    | TSS_KEY_MIGRATABLE;  // Wrapped keys must be migratable. :-(

  TSS_HKEY key;
  TSCALL(Tspi_Context_CreateObject, stuff.ctx(),
         TSS_OBJECT_TYPE_RSAKEY, init_flags, &key);
  TSS_HPOLICY key_policy;
  TSCALL(Tspi_Context_CreateObject, stuff.ctx(),
         TSS_OBJECT_TYPE_POLICY, TSS_POLICY_MIGRATION, &key_policy);

  // Set PIN.
  set_policy_secret(key_policy, key_pin);
  TSCALL(Tspi_Policy_AssignToObject, key_policy, key);

  // Load SRK public key.
  {
    UINT32 pubKeySize;
    BYTE *pubKey;
    TSCALL(Tspi_Key_GetPubKey, stuff.srk(), &pubKeySize, &pubKey);
    Tspi_Context_FreeMemory(stuff.ctx(), pubKey);
  }

  // Need to set DER mode for signing.
  TSCALL(Tspi_SetAttribUint32, key,
         TSS_TSPATTRIB_KEY_INFO,
         TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
         TSS_SS_RSASSAPKCS1V15_DER);

  // Set private key.
  TSCALL(Tspi_SetAttribData, key, TSS_TSPATTRIB_KEY_BLOB,
         TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY,
         swkey.key.size(), (BYTE*)swkey.key.data());

  // Set modulus.
  TSCALL(Tspi_SetAttribData, key,
         TSS_TSPATTRIB_RSAKEY_INFO, TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
         swkey.modulus.size(), (BYTE*)swkey.modulus.data());

  // Wrap key.
  TSCALL(Tspi_Key_WrapKey, key, stuff.srk(), 0);

  Key ret;
  ret.modulus = swkey.modulus;
  ret.exponent = swkey.exponent;

  // Get keyblob.
  UINT32 blob_size;
  BYTE* blob_blob;
  TSCALL(Tspi_GetAttribData, key,
         TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB,
         &blob_size, &blob_blob);
  ret.blob = std::string(blob_blob, blob_blob+blob_size);
  return ret;
}

Key
generate_key(const std::string* srk_pin, const std::string* key_pin, int bits) {
  TPMStuff stuff{srk_pin};

  { // Get some random data and seed the TPM with it.
    const std::string entropy = xrandom(num_random_bytes);
    TSCALL(Tspi_TPM_StirRandom, stuff.tpm(),
           entropy.size(), (BYTE*)entropy.data());
  }

  // === Set up key object ===
  int init_flags =
    TSS_KEY_TYPE_SIGNING
    | keysize_flag(bits)
    | TSS_KEY_VOLATILE
    | TSS_KEY_NOT_MIGRATABLE;

  if (key_pin) {
    init_flags |= TSS_KEY_AUTHORIZATION;
  } else {
    init_flags |= TSS_KEY_NO_AUTHORIZATION;
  }

  TSS_HKEY key;
  TSCALL(Tspi_Context_CreateObject, stuff.ctx(),
         TSS_OBJECT_TYPE_RSAKEY, init_flags, &key);
  TSS_HPOLICY key_policy;
  TSCALL(Tspi_Context_CreateObject, stuff.ctx(),
         TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &key_policy);

  set_policy_secret(key_policy, key_pin);
  TSCALL(Tspi_Policy_AssignToObject, key_policy, key);

  // Need to set DER mode for signing.
  TSCALL(Tspi_SetAttribUint32, key,
         TSS_TSPATTRIB_KEY_INFO,
         TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
         TSS_SS_RSASSAPKCS1V15_DER);

  // === Create Key ===
  TSCALL(Tspi_Key_CreateKey, key, stuff.srk(), 0);

  Key ret;
  // Get modulus.
  UINT32 mod_size;
  BYTE* mod_blob;
  TSCALL(Tspi_GetAttribData, key,
         TSS_TSPATTRIB_RSAKEY_INFO, TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
         &mod_size, &mod_blob);
  std::clog << "Modulus size: " << mod_size << std::endl;
  ret.modulus = std::string(std::string(mod_blob, mod_blob+mod_size));

  // Print the public key.
  // We extract the modulus and exponent separately instead for now.
  if (false) {
    TSCALL(Tspi_Key_LoadKey, key, stuff.srk());

    UINT32 pub_size;
    BYTE* pub;
    TSCALL(Tspi_Key_GetPubKey, key, &pub_size, &pub);
    std::clog << "Pub: " << to_hex(std::string((char*)pub, pub_size)) << std::endl;
  }

  // Get exponent.
  UINT32 exp_size;
  BYTE* exp_blob;
  TSCALL(Tspi_GetAttribData, key,
         TSS_TSPATTRIB_RSAKEY_INFO, TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT,
         &exp_size, &exp_blob);
  std::clog << "Exponent size: " << exp_size << std::endl;
  ret.exponent = std::string{std::string(exp_blob, exp_blob+exp_size)};

  // Get keysize.
  UINT32 size;
  TSCALL(Tspi_GetAttribUint32, key,
         TSS_TSPATTRIB_RSAKEY_INFO, TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
         &size);
  std::clog << "Size: " << size << std::endl;
  if ((UINT32)bits != size) {
    throw std::runtime_error("Asked for " + std::to_string(bits) + " bit key,"
                             " but got " + std::to_string(size) + " bit key,");
  }

  // Get keyblob.
  UINT32 blob_size;
  BYTE* blob_blob;
  TSCALL(Tspi_GetAttribData, key,
         TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB,
         &blob_size, &blob_blob);
  std::clog << "Blob size: " << blob_size << std::endl;
  ret.blob = std::string{std::string(blob_blob, blob_blob+blob_size)};
  return ret;
}

std::string
xbasename(const std::string& fullpath)
{
  const size_t s = fullpath.size();
  std::vector<char> buf(s + 1);
  memcpy(&buf[0], fullpath.data(), s);
  const std::string ret{basename(&buf[0])};
  return ret;
}

std::string
xgethostname()
{
    std::vector<char> buf(1024);
    if (gethostname(&buf[0], buf.size() - 1)) {
      throw std::runtime_error(std::string("gethostbyname(): ") + strerror(errno));
    }
    return &buf[0];
}

std::string
to_hex(const std::string& s)
{
  std::stringstream ss;
  for (auto c : s) {
    ss << std::setw(2) << std::setfill('0') << std::setbase(16)
       << unsigned(c & 0xff);
  }
  return ss.str();
}

std::string
to_bin(const std::string& s)
{
  std::map<std::string, unsigned char> m;
  for (int c = 0; c < 256; c++) {
    unsigned char t[2] = {(unsigned char)c, 0};
    m[to_hex((char*)t)] = c;
  }

  if (s.size() & 1) {
    throw std::runtime_error("to_bin() on odd length string");
  }
  std::string ret;
  for (unsigned c = 0; c < s.size(); c+=2) {
    auto t = s.substr(c, 2);
    ret += m[t];
  }
  return ret;
}

Key
parse_keyfile(const std::string& s)
{
  std::istringstream ss(s);
  Key key;
  int linenum = 0;
  while (!ss.eof()) {
    std::string line;
    getline(ss, line);
    linenum++;
    if (line.empty() || line[0] == '#') {
      continue;
    }

    std::istringstream linetokens{line};
    std::string cmd, rest;
    getline(linetokens, cmd, ' ');
    getline(linetokens, rest);
    if (cmd == "mod") {
      key.modulus = to_bin(rest);
    } else if (cmd == "blob") {
      key.blob = to_bin(rest);
    } else if (cmd == "exp") {
      key.exponent = to_bin(rest);
    } else {
      throw std::runtime_error("Keyfile format error(line "
                               + std::to_string(linenum) + ": " + line + ")");
    }
  }
  if (key.modulus.empty() || key.blob.empty() || key.exponent.empty()) {
    throw std::runtime_error("Keyfile incomplete. Needs modulus, exponent and blob.");
  }
  return key;
}

bool
auth_required(const std::string* srk_pin, const Key& key)
{
  TPMStuff stuff{srk_pin};

  int init_flags =
    TSS_KEY_TYPE_SIGNING
    | TSS_KEY_VOLATILE
    | TSS_KEY_NO_AUTHORIZATION
    | TSS_KEY_NOT_MIGRATABLE;

  TSS_HKEY hkey;
  TSCALL(Tspi_Context_CreateObject, stuff.ctx(), TSS_OBJECT_TYPE_RSAKEY,
         init_flags, &hkey);
  TSCALL(Tspi_Context_LoadKeyByBlob, stuff.ctx(), stuff.srk(),
         key.blob.size(), (BYTE*)key.blob.data(), &hkey);

  UINT32 auth;
  // TODO: AUTHUSAGE or AUTHDATAUSAGE?
  TSCALL(Tspi_GetAttribUint32, hkey,
         TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE,
         &auth);
  return !!auth;
}

std::string
slurp_file(const std::string& fn)
{
  std::ifstream f(fn);
  if (!f) {
    throw std::runtime_error("Can't open file '" + fn + "'");
  }
  return std::string{std::istreambuf_iterator<char>(f),
                     std::istreambuf_iterator<char>()};
}

// Set password/PIN on a policy. If nullptr pin is given, use the Well Known Secret.
void
set_policy_secret(TSS_HPOLICY policy, const std::string* pin)
{
  if (pin) {
    TSCALL(Tspi_Policy_SetSecret, policy,
           TSS_SECRET_MODE_PLAIN,
           pin->size(),
           (BYTE*)pin->data());
  } else {
    BYTE wks[] = TSS_WELL_KNOWN_SECRET;
    int wks_size = sizeof(wks);
    TSCALL(Tspi_Policy_SetSecret, policy,
           TSS_SECRET_MODE_SHA1, wks_size, wks);
  }
}

/**
 * https://www.cylab.cmu.edu/tiw/slides/challener-TPM.pdf
 * TODO: this doesn't work yet.
 */
SoftwareKey
exfiltrate_key(const Key& key,
               const std::string* srk_pin,
               const std::string& owner_password,
               const std::string* key_pin)
{
  TPMStuff stuff{srk_pin};

  // === Load key ===
  int init_flags =
    TSS_KEY_TYPE_SIGNING
    | TSS_KEY_VOLATILE
    | TSS_KEY_NO_AUTHORIZATION
    | TSS_KEY_MIGRATABLE;
  TSS_HKEY sign;
  TSS_HPOLICY policy_sign;
  TSCALL(Tspi_Context_CreateObject, stuff.ctx(), TSS_OBJECT_TYPE_RSAKEY,
         init_flags, &sign);
  TSCALL(Tspi_Context_LoadKeyByBlob, stuff.ctx(), stuff.srk(),
         key.blob.size(), (BYTE*)key.blob.data(), &sign);
  TSCALL(Tspi_Context_CreateObject, stuff.ctx(),
         TSS_OBJECT_TYPE_POLICY, TSS_POLICY_MIGRATION,
         &policy_sign);
  set_policy_secret(policy_sign, key_pin);
  TSCALL(Tspi_Policy_AssignToObject, policy_sign, sign);

  // Set owner password.
  {
    TSS_HPOLICY policy_tpm;
    TSCALL(Tspi_GetPolicyObject, stuff.tpm(), TSS_POLICY_USAGE, &policy_tpm);
    set_policy_secret(policy_tpm, &owner_password);
  }

  // Generate migration ticket.
  BYTE* ticket;
  UINT32 ticket_size;
  TSCALL(Tspi_TPM_AuthorizeMigrationTicket,
         stuff.tpm(),
         stuff.srk(),   // TODO: change to target key.
         TSS_MS_REWRAP,
         &ticket_size, &ticket);

  // Create migration blob.
  BYTE* rnd;
  UINT32 rnd_size;
  BYTE* migrblob;
  UINT32 migrblob_size;
  TSCALL(Tspi_Key_CreateMigrationBlob,
         sign,                        // Key to migrate.
         stuff.srk(),                 // Parent key.
         ticket_size, ticket,         // Migration ticket.
         &rnd_size, &rnd,             // Random data.
         &migrblob_size, &migrblob);  // Migration data blob.

  // TODO: Decrypt migration blob.
  return SoftwareKey();
}

std::string
sign(const Key& key, const std::string& data,
     const std::string* srk_pin,
     const std::string* key_pin)
{
  TPMStuff stuff{srk_pin};

  // === Load key ===
  int init_flags =
    TSS_KEY_TYPE_SIGNING
    | TSS_KEY_VOLATILE
    | TSS_KEY_NO_AUTHORIZATION
    | TSS_KEY_NOT_MIGRATABLE;
  TSS_HKEY sign;
  TSS_HPOLICY policy_sign;
  TSCALL(Tspi_Context_CreateObject, stuff.ctx(), TSS_OBJECT_TYPE_RSAKEY,
         init_flags, &sign);
  TSCALL(Tspi_Context_LoadKeyByBlob, stuff.ctx(), stuff.srk(),
         key.blob.size(), (BYTE*)key.blob.data(), &sign);
  TSCALL(Tspi_Context_CreateObject, stuff.ctx(),
         TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
         &policy_sign);

  set_policy_secret(policy_sign, key_pin);
  TSCALL(Tspi_Policy_AssignToObject, policy_sign, sign);

  // === Sign ===
  TSS_HHASH hash;
  UINT32 sig_size;
  BYTE* sig_blob;
  TSCALL(Tspi_Context_CreateObject, stuff.ctx(),
         TSS_OBJECT_TYPE_HASH, TSS_HASH_OTHER, &hash);
  TSCALL(Tspi_Hash_SetHashValue, hash, data.size(), (BYTE*)data.data());
  if (false) {
    TSCALL(Tspi_SetAttribUint32, sign, TSS_TSPATTRIB_KEY_INFO,
           TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
           TSS_SS_RSASSAPKCS1V15_DER);
  }
  TSCALL(Tspi_Hash_Sign, hash, sign, &sig_size, &sig_blob);
  return std::string{sig_blob, sig_blob+sig_size};
}

class Defer {
 public:
  Defer(std::function<void()> f): f_(f) {}
  ~Defer()
  {
    try {
      f_();
    } catch (const std::exception& e) {
      std::clog << "Exception thrown in deferred code.\n";
      throw;
    }
  }
 private:
  std::function<void()> f_;
};

std::string
public_decrypt(const Key& key, const std::string& sig)
{
  // Load key.
  RSA *rsa = RSA_new();
  Defer dfr([&rsa]{RSA_free(rsa);});
  rsa->n = string2bn(key.modulus);
  rsa->e = string2bn(key.exponent);

  // Decrypt signature.
  std::vector<unsigned char> d(RSA_size(rsa));
  const int len = RSA_public_decrypt(
      sig.size(),
      reinterpret_cast<const unsigned char*>(sig.data()),
      &d[0],
      rsa,
      RSA_PKCS1_PADDING);
  if (len < 0) {
    throw std::runtime_error(xsprintf("RSA_public_decrypt failed: %s", ERR_error_string(ERR_get_error(), NULL)));
  }
  return std::string{&d[0], &d[len]};
}

bool
verify(const Key& key, const std::string& data, const std::string& sig)
{
  // TODO: Make this comparison constant time.
  if (data != public_decrypt(key, sig)) {
    return false;
  }
  return true;
}
END_NAMESPACE(stpm);
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
