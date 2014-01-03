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
#include"tspiwrap.h"

#include"common.h"
#include"internal.h"

BEGIN_NAMESPACE(stpm);

TspiContext::TspiContext()
  :ctx_(0)
{
  TSCALL(Tspi_Context_Create, &ctx_);
  try {
    TSCALL(Tspi_Context_Connect, ctx_, NULL);
  } catch (...) {
    TSCALL(Tspi_Context_FreeMemory, ctx_, NULL);
    TSCALL(Tspi_Context_Close, ctx_);
    throw;
  }
}

TspiContext::~TspiContext()
{
  Tspi_Context_FreeMemory(ctx_, NULL);
  Tspi_Context_Close(ctx_);
}

TspiTPM::TspiTPM(TspiContext&ctx)
  :tpm_(0)
{
  TSCALL(Tspi_Context_GetTpmObject, ctx.ctx(), &tpm_);
}

TspiTPM::~TspiTPM()
{
  // TODO: Something should be freed here, right?
}

TspiKey::TspiKey(TspiContext& ctx, TSS_UUID uuid, const std::string* pin)
  :ctx_(ctx),
   key_(0),
   policy_(0)
{
  try {
    TSCALL(Tspi_Context_CreateObject, ctx_.ctx(),
           TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_TSP_SRK, &key_);

    TSCALL(Tspi_Context_LoadKeyByUUID, ctx_.ctx(),
           TSS_PS_TYPE_SYSTEM, uuid, &key_);

    TSCALL(Tspi_Context_CreateObject, ctx_.ctx(),
           TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &policy_);

    set_policy_secret(policy_, pin);
    TSCALL(Tspi_Policy_AssignToObject, policy_, key_);
  } catch (...) {
    destroy();
    throw;
  }
}

TspiKey::~TspiKey()
{
  destroy();
}
void TspiKey::destroy()
{
  if (policy_) {
    Tspi_Context_CloseObject(ctx_.ctx(), policy_);
  }
  if (key_) {
    Tspi_Context_CloseObject(ctx_.ctx(), key_);
  }
}

TPMStuff::TPMStuff(const std::string* srk_pin)
  :tpm_(ctx_),
   srk_(ctx_, srk_uuid, srk_pin)
{
}
END_NAMESPACE(stpm);
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
