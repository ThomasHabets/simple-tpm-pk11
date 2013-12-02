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
// Wrapping classes to make cleanup easier.
#ifndef __INCLUDE__SIMPLE_TPM_PK11_TSPIWRAP_H__
#define __INCLUDE__SIMPLE_TPM_PK11_TSPIWRAP_H__

#include<string>

#include"tss/tspi.h"

namespace stpm {
#if 0
}
#endif

class TspiContext {
public:
  TspiContext(const TspiContext&) = delete;
  TspiContext& operator=(const TspiContext&) = delete;
  TspiContext();
  ~TspiContext();

  TSS_HCONTEXT ctx() const { return ctx_; }
private:
  TSS_HCONTEXT ctx_;
};

class TspiTPM {
public:
  TspiTPM(const TspiTPM&) = delete;
  TspiTPM& operator=(const TspiTPM&) = delete;
  TspiTPM(TspiContext&ctx);
  ~TspiTPM();

  TSS_HTPM tpm() { return tpm_; }
private:
  TSS_HTPM tpm_;
};

class TspiKey {
public:
  TspiKey(const TspiKey&) = delete;
  TspiKey& operator=(const TspiKey&) = delete;
  TspiKey(TspiContext&, TSS_UUID uuid, const std::string* pin);
  ~TspiKey();

  TSS_HKEY key() const { return key_; }
private:
  TspiContext& ctx_;
  TSS_HKEY key_;
  TSS_HPOLICY policy_;

  void destroy();
};

class TPMStuff {
public:
  TPMStuff(const TPMStuff&) = delete;
  TPMStuff& operator=(const TPMStuff&) = delete;
  TPMStuff(const std::string* srk_pin);

  TSS_HCONTEXT ctx() { return ctx_.ctx(); }
  TSS_HTPM tpm() { return tpm_.tpm(); }
  TSS_HKEY srk() { return srk_.key(); }
private:
  // Order matters. Do not change.
  TspiContext ctx_;
  TspiTPM tpm_;
  TspiKey srk_;
};
}  // namespace stpm
#endif
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
