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
#include<memory>
#include<stdexcept>
#include<string>

#include<opencryptoki/pkcs11.h>

class PK11Error: public std::exception {
 public:
  PK11Error(int code): code(code), msg(get_msg()) {}
  PK11Error(int code, const std::string& msg)
    :code(code),
     msg(get_msg() + ": " + msg)
  {
  }
  virtual ~PK11Error() throw() {}

  const int code;
  const std::string msg;
 private:
  std::string get_msg() const;
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

 private:
  void read_file(std::ifstream&);
};

class Session {
public:
  Session(const Config&);

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
  int findpos_;
};
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
