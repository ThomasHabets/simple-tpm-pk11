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
objectClass(CK_OBJECT_HANDLE hObject)
{
  return (hObject == 1) ? CKO_PUBLIC_KEY : CKO_PRIVATE_KEY;
}

Session::Session(const Config& config)
    :config_(config),
     findpos_(0)
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
  filters_ = filters;
  nfilters_ = nfilters;
}

int
Session::FindObjects(CK_OBJECT_HANDLE_PTR obj, int maxobj)
{
  int numFound = 0;
  for(; numFound < maxobj && findpos_ <= 2; findpos_++) {
    bool filterRejected = false;
    for(int i = 0; i < nfilters_; i++) {
      if(filters_[i].type == CKA_CLASS) {
        if(*(CK_OBJECT_CLASS *)filters_[i].pValue != objectClass(findpos_)) {
          filterRejected = true;
          break;
        }
      } else {
        // Ignore all other filters
      }
    }
    if(!filterRejected) {
      obj[numFound++] = findpos_;
    }
  }
  return numFound;
}

void
Config::debug_log(const char* fmt, ...) {
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
    stpm::do_log(logfile_.get(), stpm::xctime() + " DEBUG " + std::string(buf.begin(), buf.end()));
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

  for (unsigned i = 0; i < usCount; i++) {
    switch (pTemplate[i].type) {
    case CKA_ID:
      config_.debug_log("   Attribute %d: ID", i);
      // TODO: populate properly.
      pTemplate[i].ulValueLen = 10; // ID
      break;

    case CKA_MODULUS:
      config_.debug_log("   Attribute %d: Modulus size %d",
                        i, key.modulus.size());
      pTemplate[i].ulValueLen = key.modulus.size();
      if (pTemplate[i].pValue) {
        memcpy(pTemplate[i].pValue, key.modulus.data(), key.modulus.size());
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

    default:
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
