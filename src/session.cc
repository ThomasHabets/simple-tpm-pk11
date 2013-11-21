#include"session.h"

#include<cstring>
#include<sstream>
#include<iostream>
#include<fstream>
#include<iterator>
#include<tuple>

#include"common.h"

#include <openssl/bn.h>

// Optionally shell out to openssl for the RSA operation.
// Get pubkey of a cert using something like:
// openssl x509 -in foo.crt -pubkey
// TODO: remove this openssl stuff, or make it fully supported.
#define USE_OPENSSL_FOR_TESTING 0

std::string
PK11Error::get_msg() const
{
  std::stringstream ss;
  ss << "Code=" << code;
  return ss.str();
}


Session::Session(int slot)
  :slot_(slot),
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
  *obj = 0;
  findpos_++;
  return 1;
}

void
Session::GetAttributeValue(CK_OBJECT_HANDLE hObject,
                           CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount)
{
  const std::string keyfile{"genkey3"};
  std::ifstream kf{keyfile};
  if (!kf) {
    throw PK11Error(CKR_GENERAL_ERROR,
                    "Failed to open key file '" + keyfile + "'");
  }
  const std::string kfs{std::istreambuf_iterator<char>(kf),
                        std::istreambuf_iterator<char>()};
  const stpm::Key key = stpm::parse_keyfile(kfs);
  const std::string exp = stpm::to_hex(key.exponent);
  const std::string mod = stpm::to_hex(key.modulus);
  // TODO: actually check what was asked for. Currently assuming id,
  // mod, exponent since that's what the SSH client sent.

  // For polling of space needed. TODO: actual sizes here.
  pTemplate[0].ulValueLen = 1000000; // ID
  pTemplate[1].ulValueLen = mod.size();
  pTemplate[2].ulValueLen = exp.size();

  if (pTemplate[0].pValue) {
    // TODO: don't hard code key. Get it from ~/.simple-tpm-pk11/config.
    BIGNUM *bnm = NULL;
    BN_hex2bn(&bnm, mod.c_str());
    int mlen = BN_bn2bin(bnm, (unsigned char*)pTemplate[1].pValue);

    BIGNUM *bne = NULL;
    BN_hex2bn(&bne, exp.c_str());
    int elen = BN_bn2bin(bne, (unsigned char*)pTemplate[2].pValue);

    pTemplate[1].ulValueLen = mlen;
    pTemplate[2].ulValueLen = elen;
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
#if USE_OPENSSL_FOR_TESTING
  FILE *f;
  if (!(f = fopen("to-sign", "w"))) {
    throw "Rocks";
  }
  fwrite(pData, usDataLen, 1, f);
  fclose(f);
  system("openssl rsautl -sign -inkey rsa-key -out signed -in to-sign");
  if (!(f = fopen("signed", "r"))) {
    throw "Rocks";
  }
  int r;
  r = fread(pSignature, 1, *pusSignatureLen, f);
  fclose(f);
  printf("HABETS: asked to sign %p (len %d), output %d bytes\n", pData, usDataLen, r);
  *pusSignatureLen = r;
#else
    // TODO: don't hard code key. Get it from ~/.simple-tpm-pk11/config.
  const std::string keyfile{"genkey3"};
  std::ifstream kf(keyfile);
  if (!kf) {
    throw PK11Error(CKR_GENERAL_ERROR,
                    "Failed to open key file '" + keyfile + "'");
  }
  const std::string kfs{std::istreambuf_iterator<char>(kf),
                        std::istreambuf_iterator<char>()};
  const stpm::Key key = stpm::parse_keyfile(kfs);
  const std::string data{pData, pData+usDataLen};
  const std::string signature{stpm::sign(key, data)};
  *pusSignatureLen = signature.size();
  memcpy(pSignature, signature.data(), signature.size());
  std::cout << "HABETS: signing %s " << stpm::to_hex(data)
            << " (len " << data.size() << ")"
            << ", output " << *pusSignatureLen << " bytes\n";
#endif
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
