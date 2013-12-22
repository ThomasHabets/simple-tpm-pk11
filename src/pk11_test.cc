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

class PK11Test: public ::testing::Test {
public:
  void SetUp()
  {
    setenv("SIMPLE_TPM_PK11_CONFIG", "testdata/pk11.config", 1);
    setenv("SIMPLE_TPM_PK11_DEBUG", "on", 1);
    EXPECT_EQ(CKR_OK, C_GetFunctionList(&func_));
    EXPECT_EQ(CKR_OK, func_->C_Initialize(h_));
  }
  void TearDown()
  {
    EXPECT_EQ(CKR_OK, func_->C_Finalize(h_));
  }

protected:
  CK_FUNCTION_LIST *func_;
  void* h_;
};

TEST_F(PK11Test, GetInfo)
{
  CK_INFO info;
  EXPECT_EQ(CKR_OK, func_->C_GetInfo(&info));
  EXPECT_EQ(0, info.cryptokiVersion.major);
  EXPECT_EQ(1, info.cryptokiVersion.minor);
  EXPECT_EQ(0, info.libraryVersion.major);
  EXPECT_EQ(1, info.libraryVersion.minor);
  EXPECT_EQ("simple-tpm-pk11 manufacturer",
            std::string((char*)info.manufacturerID));
  EXPECT_EQ("simple-tpm-pk11 library",
            std::string((char*)info.libraryDescription));
}

TEST_F(PK11Test, Sign)
{
  // TODO: actually test correct output.
  CK_SESSION_HANDLE s;
  EXPECT_EQ(CKR_OK, func_->C_OpenSession(0, 0, nullptr, nullptr, &s));

  CK_MECHANISM mech = {
    CKM_RSA_PKCS, NULL_PTR, 0
  };

  CK_OBJECT_HANDLE key;
  // TODO: Get first key.

  CK_BYTE data[35];
  CK_BYTE signature[20];
  CK_ULONG slen;
  EXPECT_EQ(CKR_OK, func_->C_SignInit(s, &mech, key));
  EXPECT_EQ(CKR_OK, func_->C_Sign(s, data, sizeof(data), signature, &slen));
  EXPECT_EQ(CKR_OK, func_->C_CloseSession(s));
}
