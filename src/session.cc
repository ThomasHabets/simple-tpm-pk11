#include"session.h"

#include<cassert>
#include<cstring>
#include<fstream>
#include<iostream>
#include<iterator>
#include<libgen.h>
#include<sstream>
#include<vector>

#include <openssl/bn.h>

#include"common.h"
#include"internal.h"

BEGIN_NAMESPACE();

// Like dirname(3), but always returns a string ending in '/', thus
// always being safe for appeding a filename to.
std::string
xdirname(const std::string& relative)
{
  std::vector<char> buf(relative.size()+1);
  memcpy(&buf[0], relative.data(), relative.size());
  const std::string ret{dirname(&buf[0])};
  if (ret == "/") {
    return ret;
  }
  return ret + "/";
}
END_NAMESPACE();

std::string
PK11Error::get_msg() const
{
  std::stringstream ss;
  ss << "Code=" << code;
  return ss.str();
}

Config::Config(const std::string& fn)
  :configfile_(fn),
   logfile_(new std::ofstream),
   debug_(false)

{
  std::ifstream f{fn};
  if (!f) {
    throw "TODO: opening config file failed";
  }
  read_file(f);
  if (*logfile_) {
    logfile_->open(logfilename_, std::ofstream::app);
    if (!logfile_) {
      throw "Unable to open logfile " + logfilename_;
    }
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
      keyfile_ = xdirname(configfile_) + rest;
    } else if (cmd == "log") {
      logfilename_ = xdirname(configfile_) + rest;
    } else if (cmd == "debug") {
      debug_ = true;
    } else {
      throw "TODO: unknown config line: " + line;
    }
  }
}

Session::Session(const Config& config)
    :config_(config),
     findpos_(0)
{
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
  std::ifstream kf{config_.keyfile_};
  if (!kf) {
    throw PK11Error(CKR_GENERAL_ERROR,
                    "Failed to open key file '" + config_.keyfile_ + "'");
  }
  const std::string kfs{std::istreambuf_iterator<char>(kf),
                        std::istreambuf_iterator<char>()};
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
      *config_.logfile_ << stpm::xctime()
                        << " unknown attribute: "
                        << pTemplate[i].type << std::endl << std::flush;
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
  std::ifstream kf(config_.keyfile_);
  if (!kf) {
    throw PK11Error(CKR_GENERAL_ERROR,
                    "Failed to open key file '" + config_.keyfile_ + "'");
  }
  const std::string kfs{std::istreambuf_iterator<char>(kf),
                        std::istreambuf_iterator<char>()};
  const stpm::Key key = stpm::parse_keyfile(kfs);
  const std::string data{pData, pData+usDataLen};
  const std::string signature{stpm::sign(key, data)};
  *pusSignatureLen = signature.size();
  memcpy(pSignature, signature.data(), signature.size());

  *config_.logfile_ << stpm::xctime()
                    << " signing " << data.size() << " bytes."
                    << std::endl;
  if (config_.debug_) {
    *config_.logfile_ << stpm::xctime()
                      << " DEBUG signing " << stpm::to_hex(data)
                      << " (len " << data.size() << ")"
                      << ", output " << *pusSignatureLen << " bytes"
                      << std::endl;
  }
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
