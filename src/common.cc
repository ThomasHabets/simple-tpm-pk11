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
#include<cstdio>
#include<cstring>
#include<fstream>
#include<functional>
#include<iomanip>
#include<iostream>
#include<map>
#include<sstream>
#include<string>

#include"tss/tspi.h"
#include"trousers/trousers.h"

#include"common.h"
#include"internal.h"

std::ostream& operator<<(std::ostream& o, struct stpm::Key& key)
{
  o << "mod=" << stpm::to_hex(key.modulus)
    << ",exp=" << stpm::to_hex(key.exponent)
    << ",blob=" << stpm::to_hex(key.blob);
  return o;
}

BEGIN_NAMESPACE(stpm);

BEGIN_NAMESPACE();
// TODO: Make key secret dynamic.
BYTE key_secret[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};


// Jumpgate to tscall()
#define TSCALL(x, ...) tscall(#x, [&]()->TSS_RESULT{return x(__VA_ARGS__);})

// Wrap Tspi_* calls, checking return value and throwing exception.
// TODO: Adding debug logging.
TSS_RESULT
tscall(const std::string& name, std::function<TSS_RESULT()> func)
{
  TSS_RESULT res;
  if (TSS_SUCCESS != (res = func())) {
    throw name + "(): " + parseError(res);
  }
  return res;
}
END_NAMESPACE();

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
parseError(int code)
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

Key
generate_key() {
  // === Set up context ===
  TSS_HCONTEXT ctx;
  TSCALL(Tspi_Context_Create, &ctx);
  TSCALL(Tspi_Context_Connect, ctx, NULL);

  // === Load TPM ===
  TSS_HTPM hTPM;
  TSCALL(Tspi_Context_GetTpmObject, ctx, &hTPM);

  // === Load SRK ===
  TSS_HKEY srk;
  TSCALL(Tspi_Context_CreateObject, ctx,
         TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_TSP_SRK, &srk);

  TSS_UUID uuid_srk = TSS_UUID_SRK;
  TSCALL(Tspi_Context_LoadKeyByUUID, ctx,
         TSS_PS_TYPE_SYSTEM, uuid_srk, &srk);

  TSS_HKEY srk_policy;
  TSCALL(Tspi_Context_CreateObject, ctx,
         TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &srk_policy);

  // TODO: support non-WKS SRK passwords.
  BYTE wks[] = TSS_WELL_KNOWN_SECRET;
  int wks_size = sizeof(wks);
  TSCALL(Tspi_Policy_SetSecret, srk_policy,
         TSS_SECRET_MODE_SHA1, wks_size, wks);

  TSCALL(Tspi_Policy_AssignToObject, srk_policy, srk);

  // === Set up key object ===
  int init_flags = 
    TSS_KEY_TYPE_SIGNING
    | TSS_KEY_SIZE_2048
    | TSS_KEY_VOLATILE
    | TSS_KEY_NO_AUTHORIZATION
    | TSS_KEY_NOT_MIGRATABLE;

  TSS_HKEY key;
  TSCALL(Tspi_Context_CreateObject, ctx,
         TSS_OBJECT_TYPE_RSAKEY, init_flags, &key);
  TSS_HPOLICY key_policy;
  TSCALL(Tspi_Context_CreateObject, ctx,
         TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &key_policy);

  TSCALL(Tspi_Policy_SetSecret, key_policy,
         TSS_SECRET_MODE_SHA1, sizeof(key_secret), key_secret);
  TSCALL(Tspi_Policy_AssignToObject, key_policy, key);

  // Need to set DER mode for signing.
  TSCALL(Tspi_SetAttribUint32,key,
         TSS_TSPATTRIB_KEY_INFO,
         TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
         TSS_SS_RSASSAPKCS1V15_DER);

  // === Create Key ===
  TSCALL(Tspi_Key_CreateKey, key, srk, 0);

  Key ret;
  // Get modulus.
  UINT32 mod_size;
  BYTE* mod_blob;
  TSCALL(Tspi_GetAttribData, key,
         TSS_TSPATTRIB_RSAKEY_INFO, TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
         &mod_size, &mod_blob);
  std::clog << "Modulus size: " << mod_size << std::endl;
  ret.modulus = std::string(std::string(mod_blob, mod_blob+mod_size));

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
  
  // Get keyblob.
  UINT32 blob_size;
  BYTE* blob_blob;
  TSCALL(Tspi_GetAttribData, key,
         TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB,
         &blob_size, &blob_blob);
  std::clog << "Blob size: " << blob_size << std::endl;
  ret.blob = std::string{std::string(blob_blob, blob_blob+blob_size)};

  // Cleanup
  // TODO; confirm that this cleans up everything.
  //Tspi_Context_Close(h);
  Tspi_Context_FreeMemory(ctx, NULL);
  Tspi_Context_Close(ctx);
  return ret;
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
    throw "to_bin() on odd length string";
  }
  std::string ret;
  for (unsigned c = 0; c < s.size(); c+=2) {
    auto t = s.substr(c, 2);
    ret += m[t];
  }
  return ret;
}

Key
parse_keyfile(const std::string &s)
{
  std::istringstream ss(s);
  Key key;
  while (!ss.eof()) {
    std::string line;
    getline(ss, line);
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
      throw "Keyfile format error(line=" + line + ")";
    }
  }
  if (key.modulus.empty() || key.blob.empty() || key.exponent.empty()) {
    throw "Keyfile incomplete. TODO: better error.";
  }
  return key;
}

std::string
sign(const Key& key, const std::string& data)
{
  BYTE wks[] = TSS_WELL_KNOWN_SECRET;
  UINT32 wks_size = sizeof(wks);

  // === Context ===
  TSS_HCONTEXT ctx;
  TSCALL(Tspi_Context_Create, &ctx);
  TSCALL(Tspi_Context_Connect, ctx, NULL);

  // === TPM ===
  TSS_HTPM tpm;
  TSCALL(Tspi_Context_GetTpmObject, ctx, &tpm);

  // === SRK ===
  TSS_HKEY srk;
  TSS_UUID uuid_srk = TSS_UUID_SRK;
  TSCALL(Tspi_Context_CreateObject, ctx,
         TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_TSP_SRK, &srk);
  TSCALL(Tspi_Context_LoadKeyByUUID, ctx,
         TSS_PS_TYPE_SYSTEM, uuid_srk, &srk);

  TSS_HPOLICY policy_srk;
  TSCALL(Tspi_Context_CreateObject, ctx,
         TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &policy_srk);
  TSCALL(Tspi_Policy_SetSecret, policy_srk, TSS_SECRET_MODE_SHA1,
         wks_size, wks);
  TSCALL(Tspi_Policy_AssignToObject, policy_srk, srk);

  // === Load key ===
  int init_flags = 
    TSS_KEY_TYPE_SIGNING
    | TSS_KEY_SIZE_2048
    | TSS_KEY_VOLATILE
    | TSS_KEY_NO_AUTHORIZATION
    | TSS_KEY_NOT_MIGRATABLE;
  TSS_HKEY sign;
  TSS_HPOLICY policy_sign;
  TSCALL(Tspi_Context_CreateObject, ctx, TSS_OBJECT_TYPE_RSAKEY,
         init_flags, &sign);
  TSCALL(Tspi_Context_LoadKeyByBlob, ctx, srk,
         key.blob.size(), (BYTE*)key.blob.data(), &sign);
  TSCALL(Tspi_Context_CreateObject, ctx,
         TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
         &policy_sign);

  TSCALL(Tspi_Policy_SetSecret, policy_sign, TSS_SECRET_MODE_SHA1,
         sizeof(key_secret), key_secret);
  TSCALL(Tspi_Policy_AssignToObject, policy_sign, sign);
        
  // === Sign ===
  TSS_HHASH hash;
  UINT32 sig_size;
  BYTE* sig_blob;
  TSCALL(Tspi_Context_CreateObject, ctx,
         TSS_OBJECT_TYPE_HASH, TSS_HASH_OTHER, &hash);
  TSCALL(Tspi_Hash_SetHashValue, hash, data.size(), (BYTE*)data.data());
  if (false) {
    TSCALL(Tspi_SetAttribUint32, sign, TSS_TSPATTRIB_KEY_INFO,
           TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
           TSS_SS_RSASSAPKCS1V15_DER);
  }
  TSCALL(Tspi_Hash_Sign, hash, sign, &sig_size, &sig_blob);
  const std::string ret{sig_blob, sig_blob+sig_size};

  // === Cleanup ===
  // TODO; confirm that this cleans up everything.
  Tspi_Context_FreeMemory(ctx, NULL);
  Tspi_Context_Close(ctx);
  return ret;
}
END_NAMESPACE(stpm);
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
