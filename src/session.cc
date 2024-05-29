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
#include"session.h"

#include<cassert>
#include<cstring>
#include<fstream>
#include<iostream>
#include<iterator>
#include<libgen.h>
#include<sstream>
#include<vector>
#include<cstdarg>

#include<openssl/bn.h>

#include"common.h"
#include"internal.h"

BEGIN_NAMESPACE();

// Like dirname(3), but always returns a string ending in '/', thus
// always being safe for appeding a filename to.
std::string
xdirname(const std::string& relative)
{
  const size_t s = relative.size();
  std::vector<char> buf(s + 1);
  memcpy(&buf[0], relative.data(), s);
  const std::string ret{dirname(&buf[0])};
  if (ret == "/") {
    return ret;
  }
  return ret + "/";
}
END_NAMESPACE();

Config::Config(const std::string& fn)
  :configfile_(fn),
   logfile_(new std::ofstream),
   set_srk_pin_(false),
   set_key_pin_(false),
   debug_(false)
{
  std::ifstream f{fn};
  if (!f) {
    throw std::runtime_error("Opening config file " + fn + " failed");
  }
  read_file(f);
  if (*logfile_) {
    logfile_->open(logfilename_, std::ofstream::app);
    if (!logfile_) {
      throw std::runtime_error("Unable to open logfile " + logfilename_);
    }
  }
  if (keyfile_.empty()) {
    // TODO: should use fqdn?
    keyfile_ = xdirname(configfile_) + stpm::xgethostname() + ".key";
  }
}

void
Config::read_file(std::ifstream& f)
{
  while (!f.eof()) {
    std::string line;
    getline(f, line);
    if (line.empty() || line[0] == '#') {
      continue;
    }

    std::istringstream linetokens{line};
    std::string cmd, rest;
    getline(linetokens, cmd, ' ');
    getline(linetokens, rest);

    if (cmd == "key") {
      keyfile_ = rest;
      if (keyfile_.substr(0, 1) != "/") {
        keyfile_ = xdirname(configfile_) + rest;
      }
    } else if (cmd == "log") {
      logfilename_ = rest;
      if (logfilename_.substr(0, 1) != "/") {
        logfilename_ = xdirname(configfile_) + rest;
      }
    } else if (cmd == "key_pin") {
      key_pin_ = rest;
      set_key_pin_ = true;
    } else if (cmd == "srk_pin") {
      srk_pin_ = rest;
      set_srk_pin_ = true;
    } else if (cmd == "debug") {
      debug_ = true;
    } else {
      throw std::runtime_error("Unknown config line: " + line);
    }
  }
}

static
CK_OBJECT_CLASS
object_class(CK_OBJECT_HANDLE hObject)
{
  return (hObject == 1) ? CKO_PUBLIC_KEY : CKO_PRIVATE_KEY;
}

// create deep copy
CK_ATTRIBUTE_FULL::CK_ATTRIBUTE_FULL(CK_ATTRIBUTE attr)
    :type_(attr.type), data_(static_cast<char*>(attr.pValue), static_cast<char*>(attr.pValue) + attr.ulValueLen)
{
}

Session::Session(const Config& config)
    :config_(config)
{
}

void
Session::Login(CK_USER_TYPE type, const std::string& pin)
{
  config_.key_pin_ = pin;
  config_.set_key_pin_ = true;
}

void
Session::FindObjectsInit(CK_ATTRIBUTE_PTR filters, int nfilters)
{
  findpos_ = 1; // Handles can't be 0, or cryptoki will interpret it as an error
  // create deep copy of attribute filter array
  // it's possible that the memory of attribute filter array be reclaimed by the caller
  // between the call of FindObjectsInit and FindObjects
  find_filters_ = std::vector<CK_ATTRIBUTE_FULL>(filters, filters + nfilters);
}

int
Session::FindObjects(CK_OBJECT_HANDLE_PTR obj, int maxobj)
{
  int numFound = 0;
  for (; numFound < maxobj && findpos_ <= 2; findpos_++) {
    bool filterRejected = false;
    for (auto& x : find_filters_) {
      if (x.type_ == CKA_CLASS) {
        // match object class
        // only CKO_PUBLIC_KEY and CKO_PRIVATE_KEY is allowed
        if (*reinterpret_cast<CK_OBJECT_CLASS*>(x.data_.data()) != object_class(findpos_)) {
          filterRejected = true;
          break;
        }
      } else {
        // Ignore all other filters
        // TODO: implement CKA_ID and CKA_LABEL match
      }
    }
    if (!filterRejected) {
      obj[numFound++] = findpos_;
    }
  }
  return numFound;
}

void
Config::debug_log(const char* fmt, ...) const
{
  va_list args;
  va_start(args, fmt);

  va_list va2;
  va_copy(va2, args);

  size_t s = vsnprintf(NULL, 0, fmt, args) + 1;
  va_end(args);

  std::vector<char> buf(s);
  vsnprintf(&buf[0], s, fmt, va2);
  va_end(va2);

  if (debug_) {
    stpm::do_log(logfile_.get(), stpm::xctime() + " DEBUG " + std::string(buf.begin(), buf.end()-1));
  }
}

static bool
getPublicKeyAttribute(const Config& config, CK_ATTRIBUTE_PTR pAttribute)
{
  switch (pAttribute->type) {
  case CKA_ENCRYPT:
    config.debug_log("   Attribute: Encrypt");
    pAttribute->ulValueLen = sizeof(CK_BBOOL);
    if (pAttribute->pValue != nullptr) {
      *(CK_BBOOL *)(pAttribute->pValue) = false;
    }
    return true;

  case CKA_VERIFY:
    config.debug_log("   Attribute: Verify");
    pAttribute->ulValueLen = sizeof(CK_BBOOL);
    if (pAttribute->pValue != nullptr) {
      *(CK_BBOOL *)(pAttribute->pValue) = true;
    }
    return true;

  case CKA_VERIFY_RECOVER:
    config.debug_log("   Attribute: Verify Recover");
    pAttribute->ulValueLen = sizeof(CK_BBOOL);
    if (pAttribute->pValue != nullptr) {
      *(CK_BBOOL *)(pAttribute->pValue) = false;
    }
    return true;

  case CKA_WRAP:
    config.debug_log("   Attribute: Wrap");
    pAttribute->ulValueLen = sizeof(CK_BBOOL);
    if (pAttribute->pValue != nullptr) {
      *(CK_BBOOL *)(pAttribute->pValue) = false;
    }
    return true;

  case CKA_TRUSTED:
    config.debug_log("   Attribute: Trusted");
    pAttribute->ulValueLen = sizeof(CK_BBOOL);
    if (pAttribute->pValue != nullptr) {
      *(CK_BBOOL *)(pAttribute->pValue) = true;
    }
    return true;

  default:
    return false;
  }
}

static bool
getPrivateKeyAttribute(const Config& config, CK_ATTRIBUTE_PTR pAttribute)
{
  switch (pAttribute->type) {
  case CKA_SENSITIVE:
    config.debug_log("   Attribute: Sensitive");
    pAttribute->ulValueLen = sizeof(CK_BBOOL);
    if (pAttribute->pValue != nullptr) {
      *(CK_BBOOL *)(pAttribute->pValue) = true;
    }
    return true;

  case CKA_DECRYPT:
    config.debug_log("   Attribute: Decrypt");
    pAttribute->ulValueLen = sizeof(CK_BBOOL);
    if (pAttribute->pValue != nullptr) {
      *(CK_BBOOL *)(pAttribute->pValue) = false;
    }
    return true;

  case CKA_SIGN:
    config.debug_log("   Attribute: Sign");
    pAttribute->ulValueLen = sizeof(CK_BBOOL);
    if (pAttribute->pValue != nullptr) {
      *(CK_BBOOL *)(pAttribute->pValue) = true;
    }
    return true;

  case CKA_SIGN_RECOVER:
    config.debug_log("   Attribute: Sign Recover");
    pAttribute->ulValueLen = sizeof(CK_BBOOL);
    if (pAttribute->pValue != nullptr) {
      *(CK_BBOOL *)(pAttribute->pValue) = false;
    }
    return true;

  case CKA_UNWRAP:
    config.debug_log("   Attribute: Unwrap");
    pAttribute->ulValueLen = sizeof(CK_BBOOL);
    if (pAttribute->pValue != nullptr) {
      *(CK_BBOOL *)(pAttribute->pValue) = false;
    }
    return true;

  case CKA_EXTRACTABLE:
    config.debug_log("   Attribute: Extractable");
    pAttribute->ulValueLen = sizeof(CK_BBOOL);
    if (pAttribute->pValue != nullptr) {
      *(CK_BBOOL *)(pAttribute->pValue) = false;
    }
    return true;

  case CKA_ALWAYS_SENSITIVE:
    config.debug_log("   Attribute: Always Sensitive");
    pAttribute->ulValueLen = sizeof(CK_BBOOL);
    if (pAttribute->pValue != nullptr) {
      *(CK_BBOOL *)(pAttribute->pValue) = true;
    }
    return true;

  case CKA_NEVER_EXTRACTABLE:
    config.debug_log("   Attribute: Never Extractable");
    pAttribute->ulValueLen = sizeof(CK_BBOOL);
    if (pAttribute->pValue != nullptr) {
      *(CK_BBOOL *)(pAttribute->pValue) = true;
    }
    return true;
#ifdef CKA_WRAP_WITH_TRUSTED
  case CKA_WRAP_WITH_TRUSTED:
    config.debug_log("   Attribute: Wrap with Trusted");
    pAttribute->ulValueLen = sizeof(CK_BBOOL);
    if (pAttribute->pValue != nullptr) {
      *(CK_BBOOL *)(pAttribute->pValue) = false;
    }
    return true;
#endif
  default:
    return false;
  }
}

void
Session::GetAttributeValue(CK_OBJECT_HANDLE hObject,
                           CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount)
{
  std::string kfs;
  try {
    kfs = stpm::slurp_file(config_.keyfile_);
  } catch (...) {
    throw PK11Error(CKR_GENERAL_ERROR,
                    "Failed to read key file '" + config_.keyfile_ + "'");
  }
  const stpm::Key key = stpm::parse_keyfile(kfs);

  // TODO: maybe ID and label can be defined in config file
  char object_id[] = "1111";
  char public_key_label[] = "simple-tpm-public-key";
  char private_key_label[] = "simple-tpm-private-key";
  char unknown_key_label[] = "simple-tpm-unknown-key";

  for (unsigned i = 0; i < usCount; i++) {
    switch (pTemplate[i].type) {
    case CKA_CLASS:
      config_.debug_log("   Attribute %d: Class", i);
      pTemplate[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
      if (pTemplate[i].pValue != nullptr) {
        *(CK_OBJECT_CLASS *)(pTemplate[i].pValue) = object_class(hObject);
      }
      break;

    case CKA_KEY_TYPE:
      config_.debug_log("   Attribute %d: Key type", i);
      pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
      if (pTemplate[i].pValue != nullptr) {
        *(CK_KEY_TYPE *)(pTemplate[i].pValue) = CKK_RSA;
      }
      break;

    case CKA_DERIVE:
      config_.debug_log("   Attribute %d: Derive", i);
      pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
      if (pTemplate[i].pValue != nullptr) {
        *(CK_BBOOL *)(pTemplate[i].pValue) = false;
      }
      break;

    case CKA_LOCAL:
      config_.debug_log("   Attribute %d: Local", i);
      pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
      if (pTemplate[i].pValue != nullptr) {
        *(CK_BBOOL *)(pTemplate[i].pValue) = true;
      }
      break;

    case CKA_ID:
      config_.debug_log("   Attribute %d: ID", i);
      // public key and private key can have the same ID according to spec
      pTemplate[i].ulValueLen = 4; // ID
      if (pTemplate[i].pValue) {
        memcpy(pTemplate[i].pValue, object_id, 4);
      }
      break;

    case CKA_MODULUS:
      config_.debug_log("   Attribute %d: Modulus size %d",
                        i, key.modulus.size());
      pTemplate[i].ulValueLen = key.modulus.size();
      if (pTemplate[i].pValue) {
        memcpy(pTemplate[i].pValue, key.modulus.data(), key.modulus.size());
      }
      break;

    case CKA_MODULUS_BITS:
      config_.debug_log("   Attribute %d: Modulus bits (unsupported) %d",
                        i, key.modulus.size());
      pTemplate[i].ulValueLen = sizeof(CK_ULONG);
      if (pTemplate[i].pValue) {
        *(CK_ULONG *)(pTemplate[i].pValue) = 2048UL;
      }
      break;

    case CKA_PUBLIC_EXPONENT:
      config_.debug_log("   Attribute %d: Exponent size %d",
                        i, key.exponent.size());
      pTemplate[i].ulValueLen = key.exponent.size();
      if (pTemplate[i].pValue) {
        memcpy(pTemplate[i].pValue, key.exponent.data(), key.exponent.size());
      }
      break;

    case CKA_SUBJECT:
      config_.debug_log("   Attribute %d: Subject (unsupported)", i);
      pTemplate[i].ulValueLen = 0;
      break;

    case CKA_VALUE:
      config_.debug_log("   Attribute %d: Value (unsupported)", i);
      pTemplate[i].ulValueLen = 0;
      break;

    case CKA_LABEL:
      config_.debug_log("   Attribute %d: Label (unsupported)", i);
      if (hObject == 1) {
        // public key
        if (pTemplate[i].pValue) {
          memcpy(pTemplate[i].pValue, public_key_label, strlen(public_key_label));
        }
        pTemplate[i].ulValueLen = strlen(public_key_label);
      } else if (hObject == 2) {
        // private key
        if (pTemplate[i].pValue) {
          memcpy(pTemplate[i].pValue, private_key_label, strlen(private_key_label));
        }
        pTemplate[i].ulValueLen = strlen(private_key_label);
      } else {
        // should not happen
        if (pTemplate[i].pValue) {
          memcpy(pTemplate[i].pValue, unknown_key_label, strlen(unknown_key_label));
        }
        pTemplate[i].ulValueLen = strlen(unknown_key_label);
      }
      break;

    case CKA_START_DATE:
    case CKA_END_DATE:
      config_.debug_log("   Attribute %d: Start or End Date (unsupported)", i);
      pTemplate[i].ulValueLen = 0;
      break;

    case 0x202: // CKA_ALWAYS_AUTHENTICATE:
      config_.debug_log("   Attribute %d: Always authenticate (unsupported)", i);
      pTemplate[i].ulValueLen = 0;
      break;

    default:
      // if (hObject == 1) {
      //   // public key
      //   if (getPublicKeyAttribute(config_, &pTemplate[i])) {
      //     continue;
      //   }
      // } else if (hObject == 2) {
      //   // private key
      //   if (getPrivateKeyAttribute(config_, &pTemplate[i])) {
      //     continue;
      //   }
      // } else {}
      // Some libraries would like to query public key attributes on private keys (or vice versa)
      // This provide some sane defaults
      if (getPublicKeyAttribute(config_, &pTemplate[i]) ||
          getPrivateKeyAttribute(config_, &pTemplate[i])) {
        continue;
      }
      config_.debug_log("   Attribute %d: Unknown (%d)", i, pTemplate[i].type);
      pTemplate[i].ulValueLen = 0;
      std::stringstream ss;
      ss << stpm::xctime()
         << " unknown attribute: "
         << pTemplate[i].type;
      stpm::do_log(config_.logfile_.get(), ss.str());
    }
  }
}

void
Session::SignInit(CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
}

void
Session::Sign(CK_BYTE_PTR pData, CK_ULONG usDataLen,
              CK_BYTE_PTR pSignature, CK_ULONG_PTR pusSignatureLen)
{
  if (pSignature == nullptr) {
    // when pSignature is NULL, we should tell caller the size of the buffer needed
    // according to the call convention mentioned in the spec
    *pusSignatureLen = 256; // signature size is 256 bytes
    return;
  }
  std::string kfs;
  try {
    kfs = stpm::slurp_file(config_.keyfile_);
  } catch (...) {
    throw PK11Error(CKR_GENERAL_ERROR,
                    "Failed to read key file '" + config_.keyfile_ + "'");
  }
  const stpm::Key key = stpm::parse_keyfile(kfs);
  const std::string data{pData, pData+usDataLen};
  const std::string signature{
    stpm::sign(key, data,
               config_.set_srk_pin_ ? &config_.srk_pin_ : NULL,
               config_.set_key_pin_ ? &config_.key_pin_ : NULL)};
  *pusSignatureLen = signature.size();
  memcpy(pSignature, signature.data(), signature.size());

  std::stringstream ss;
  ss  << stpm::xctime()
      << " signing " << data.size() << " bytes.";
  stpm::do_log(config_.logfile_.get(), ss.str());
  config_.debug_log("signing %s (len %d), output %d bytes",
                    stpm::to_hex(data).c_str(),
                    data.size(),
                    *pusSignatureLen);
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
