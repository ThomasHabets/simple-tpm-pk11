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
#include"gtest/gtest.h"

#include<opencryptoki/pkcs11.h>

namespace fake_tspi_data {
  extern int keysize;
}

TEST(PK11, GetInfo)
{
  CK_FUNCTION_LIST *fl;
  EXPECT_EQ(CKR_OK, C_GetFunctionList(&fl));
  CK_INFO info;
  EXPECT_EQ(CKR_OK, fl->C_GetInfo(&info));
  EXPECT_EQ(0, info.cryptokiVersion.major);
  EXPECT_EQ(1, info.cryptokiVersion.minor);
  EXPECT_EQ(0, info.libraryVersion.major);
  EXPECT_EQ(1, info.libraryVersion.minor);
  EXPECT_EQ("simple-tpm-pk11 manufacturer",
            std::string((char*)info.manufacturerID));
  EXPECT_EQ("simple-tpm-pk11 library",
            std::string((char*)info.libraryDescription));
}
