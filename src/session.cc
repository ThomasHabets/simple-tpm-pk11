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
  findpos_ = 0;
}

int
Session::FindObjects(CK_OBJECT_HANDLE_PTR obj, int maxobj)
{
  if (findpos_ == 1) {
    return 0;
  }
  if (maxobj == 0) {
    return 0;
  }
  *obj = 0;
  findpos_++;
  return 1;
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
      // TODO: populate properly.
      pTemplate[i].ulValueLen = 10; // ID
      break;

    case CKA_MODULUS:
      pTemplate[i].ulValueLen = key.modulus.size();
      if (pTemplate[i].pValue) {
        BIGNUM *bnm = NULL;
        // TODO: copy, instead of converting back and forth.
        BN_hex2bn(&bnm, stpm::to_hex(key.modulus).c_str());
        unsigned mlen = BN_bn2bin(bnm, (unsigned char*)pTemplate[i].pValue);
        assert(mlen == key.modulus.size());
      }
      break;

    case CKA_PUBLIC_EXPONENT:
      pTemplate[i].ulValueLen = key.exponent.size();
      if (pTemplate[i].pValue) {
        BIGNUM *bne = NULL;
        // TODO: copy, instead of converting back and forth.
        BN_hex2bn(&bne, stpm::to_hex(key.exponent).c_str());
        unsigned elen = BN_bn2bin(bne, (unsigned char*)pTemplate[i].pValue);
        assert(elen == key.exponent.size());
      }
      break;

    default:
      // TODO: handle unknowns better.
      pTemplate[i].ulValueLen = 10;
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
  if (config_.debug_) {
    ss.str("");
    ss << stpm::xctime()
       << " DEBUG signing " << stpm::to_hex(data)
       << " (len " << data.size() << ")"
       << ", output " << *pusSignatureLen << " bytes";
    stpm::do_log(config_.logfile_.get(), ss.str());
  }
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
