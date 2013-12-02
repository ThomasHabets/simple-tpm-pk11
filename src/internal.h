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
// Internal include to not pollute non-namespace parts.
#ifndef __INCLUDE__SIMPLE_TPM_PK11_INTERNAL_H__
#define __INCLUDE__SIMPLE_TPM_PK11_INTERNAL_H__
#include<functional>

#include"tss/tspi.h"

#define BEGIN_NAMESPACE(x) namespace x {
#define END_NAMESPACE(x) }

// Jumpgate to tscall()
#define TSCALL(x, ...) tscall(#x, [&]()->TSS_RESULT{return x(__VA_ARGS__);})

BEGIN_NAMESPACE(stpm);
extern TSS_UUID srk_uuid;

TSS_RESULT tscall(const std::string& name, std::function<TSS_RESULT()> func);

END_NAMESPACE(stpm);
#endif
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
