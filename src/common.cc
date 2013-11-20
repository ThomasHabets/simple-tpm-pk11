#include<cstdio>
#include<fstream>
#include<iomanip>
#include<iostream>
#include<map>
#include<sstream>
#include<string>
#include<tuple>

#include"tss/tspi.h"

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

// TODO: Make key secret dynamic.
BYTE key_secret[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};


std::string
parseErrorCode(int code)
{
  switch (code) {
  case TSS_E_KEY_NO_MIGRATION_POLICY:
    return "There's no migration policy object set for the addressed key.";
  case TSS_E_BAD_PARAMETER:
    return "One or more parameter is bad.";
  case TSS_E_INTERNAL_ERROR:
    return "Internal error.";
  case TSS_E_INVALID_HANDLE:
    return "Invalid handle.";
  case TSS_E_PS_KEY_NOTFOUND:
    return "The key cannot be found in the persistent storage database.";
  case TPM_E_BAD_PARAM_SIZE:
    return "The paramSize argument to the command has the incorrect value.";
  case TSS_E_INVALID_ATTRIB_SUBFLAG:
    return "Subflag value for attrib-functions inconsistent.";
  case TSS_E_INVALID_OBJ_ACCESS:
    return "The operation failed due to an invalid object status.";
  case TPM_E_BAD_KEY_PROPERTY:
    return "The key properties in TPM_KEY_PARMs are not supported by this TPM";
  }
  
  if (code & TSS_VENDOR_OFFSET) {
    return "Vendor: " + parseErrorCode(code - TSS_VENDOR_OFFSET);
  }
  std::stringstream ss;
  ss << std::setw(4) << std::setfill('0') << std::setbase(16) << code;
  return "Unknown code 0x" + ss.str();
}

std::string
parseError(int code)
{
  std::string layer{"Unknown"};

  switch (ERROR_LAYER(code)) {
  case TSS_LAYER_TPM:
    layer = "TPM";
    break;
  case TSS_LAYER_TDDL:
    layer = "TDDL";
    break;
  case TSS_LAYER_TCS:
    layer = "TCS";
    break;
  case TSS_LAYER_TSP:
    layer = "TSP";
    break;
  }
  const std::string err{parseErrorCode(ERROR_CODE(code))};

  return layer + ": " + err;
}

Key
generate_key() {
  TSS_RESULT res;
  TSS_HCONTEXT ctx;
  TSCALL(Tspi_Context_Create, &ctx);
  TSCALL(Tspi_Context_Connect, ctx, NULL);

  TSS_HPOLICY policy_default;
  TSCALL(Tspi_Context_GetDefaultPolicy, ctx, &policy_default);

  TSS_HTPM hTPM = 0;
  TSCALL(Tspi_Context_GetTpmObject, ctx, &hTPM);

  // === SRK ===
  TSS_HKEY srk = 0;
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

  // === Key operation ===
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

  // === Create Key
  TSCALL(Tspi_Key_CreateKey, key, srk, 0);

  Key ret;
  // Get modulus.
  UINT32 mod_size;
  BYTE* mod_blob;
  TSCALL(Tspi_GetAttribData, key,
         TSS_TSPATTRIB_RSAKEY_INFO, TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
         &mod_size, &mod_blob);
  printf("Mod: %d %p\n", mod_size, mod_blob);
  ret.modulus = std::string(std::string(mod_blob, mod_blob+mod_size));

  // Get exponent.
  UINT32 exp_size;
  BYTE* exp_blob;
  TSCALL(Tspi_GetAttribData, key,
         TSS_TSPATTRIB_RSAKEY_INFO, TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT,
         &exp_size, &exp_blob);
  printf("Exp: %d %p\n", exp_size, exp_blob);
  ret.exponent = std::string{std::string(exp_blob, exp_blob+exp_size)};

  // Get keysize.
  UINT32 size;
  TSCALL(Tspi_GetAttribUint32, key,
         TSS_TSPATTRIB_RSAKEY_INFO, TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
         &size);
  printf("Size: %d\n", size);
  
  // Get keyblob.
  UINT32 blob_size;
  BYTE* blob_blob;
  TSCALL(Tspi_GetAttribData, key,
         TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB,
         &blob_size, &blob_blob);
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
  for (int c = 0; c < s.size(); c+=2) {
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

  TSS_HPOLICY policy_default;
  TSCALL(Tspi_Context_GetDefaultPolicy, ctx, &policy_default);

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
  return ret;
}
END_NAMESPACE(stpm);
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
