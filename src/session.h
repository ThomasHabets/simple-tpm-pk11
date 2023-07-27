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
#ifndef __INCLUDE__SIMPLE_TPM_PK11_SESSION_H__
#define __INCLUDE__SIMPLE_TPM_PK11_SESSION_H__
#include<memory>
#include<sstream>
#include<stdexcept>
#include<string>
#include<vector>

#include<opencryptoki/pkcs11.h>

class PK11Error: public std::runtime_error {
public:
  PK11Error(int incode, const std::string& msg)
    :std::runtime_error("Code=" + std::to_string(unsigned(incode)) + ": " + msg),
     code(incode)
  {}
  virtual ~PK11Error() throw() {}

  const int code;
};

class Config {
public:
  Config(const std::string&);

  std::string configfile_;
  std::string keyfile_;
  std::string logfilename_;
  std::shared_ptr<std::ofstream> logfile_;

  bool set_srk_pin_;
  bool set_key_pin_;
  std::string srk_pin_;
  std::string key_pin_;
  bool debug_;

  void debug_log(const char*,...) const;

 private:
  void read_file(std::ifstream&);
};

/*
typedef struct CK_ATTRIBUTE {
  CK_ATTRIBUTE_TYPE type;
  CK_VOID_PTR pValue;
  CK_ULONG ulValueLen;
} CK_ATTRIBUTE;
*/

// deep copy of CK_ATTRIBUTE
// data_ is raw data (need to be reinterpret_cast to whatever makes sense)
class CK_ATTRIBUTE_FULL {
public:
  CK_ATTRIBUTE_FULL(CK_ATTRIBUTE); // construct from CK_ATTRIBUTE
  CK_ATTRIBUTE_TYPE type_;
  std::vector<char> data_;
};

class Session {
public:
  Session(const Config&);

  void Login(CK_USER_TYPE type, const std::string& pin);
  void FindObjectsInit(CK_ATTRIBUTE_PTR filters, int nfilters);

  // Find a couple of objects. Returns number of objects supplied.
  int FindObjects(CK_OBJECT_HANDLE_PTR obj, int maxobj);

  void GetAttributeValue(CK_OBJECT_HANDLE hObject,
                         CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount);

  void SignInit(CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
  void Sign(CK_BYTE_PTR pData, CK_ULONG usDataLen,
            CK_BYTE_PTR pSignature, CK_ULONG_PTR pusSignatureLen);
private:
  Config config_;
  std::string pin_;

  // Set up by FindObjectsInit() used as state between FindObjects()
  // calls.
  int              findpos_ = 0;
  std::vector<CK_ATTRIBUTE_FULL> find_filters_;
};
#endif
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
