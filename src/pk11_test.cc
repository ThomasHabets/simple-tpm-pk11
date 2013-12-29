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
// Test the PKCS#11 module purely through the C API.

#include"gtest/gtest.h"
#include<opencryptoki/pkcs11.h>

#include"common.h"
#include"test_util.h"

namespace fake_tspi_data {
  extern int keysize;
}

class PK11Test: public ::testing::Test {
public:
  void SetUp()
  {
    setenv("SIMPLE_TPM_PK11_CONFIG", "testdata/pk11.config", 1);
    setenv("SIMPLE_TPM_PK11_DEBUG", "on", 1);
    ASSERT_EQ(CKR_OK, C_GetFunctionList(&func_));
    ASSERT_EQ(CKR_OK, func_->C_Initialize(h_));
  }
  void TearDown()
  {
    ASSERT_EQ(CKR_OK, func_->C_Finalize(h_));
  }

protected:
  CaptureStreams cs;
  CK_FUNCTION_LIST *func_;
  void* h_;
};

TEST_F(PK11Test, GetInfo)
{
  CK_INFO info;
  ASSERT_EQ(CKR_OK, func_->C_GetInfo(&info));
  ASSERT_EQ(0, info.cryptokiVersion.major);
  ASSERT_EQ(1, info.cryptokiVersion.minor);
  ASSERT_EQ(0, info.libraryVersion.major);
  ASSERT_EQ(1, info.libraryVersion.minor);
  ASSERT_EQ("simple-tpm-pk11 manufacturer",
            std::string((char*)info.manufacturerID));
  ASSERT_EQ("simple-tpm-pk11 library",
            std::string((char*)info.libraryDescription));
}

TEST_F(PK11Test, NoConfig)
{
  setenv("SIMPLE_TPM_PK11_CONFIG", "/config/missing/here", 1);

  CK_SESSION_HANDLE s;
  ASSERT_EQ(CKR_FUNCTION_FAILED, func_->C_OpenSession(0, 0, nullptr, nullptr, &s));
}

TEST_F(PK11Test, EmptyConfig)
{
  setenv("SIMPLE_TPM_PK11_CONFIG", "/dev/null", 1);
  setenv("SIMPLE_TPM_PK11_LOG_STDERR", "on", 1);
  CK_SESSION_HANDLE s;
  ASSERT_EQ(CKR_OK, func_->C_OpenSession(0, 0, nullptr, nullptr, &s));

  CK_MECHANISM mech = {
    CKM_RSA_PKCS, NULL_PTR, 0
  };

  CK_OBJECT_HANDLE key = 0;
  // TODO: Get first key.

  CK_BYTE data[35];
  CK_BYTE signature[20];
  CK_ULONG slen;
  ASSERT_EQ(CKR_OK, func_->C_SignInit(s, &mech, key));
  ASSERT_EQ(CKR_GENERAL_ERROR, func_->C_Sign(s, data, sizeof(data), signature, &slen));
  ASSERT_NE(cs.stderr().find("/dev/" + stpm::xgethostname() + ".key"), std::string::npos);
}

TEST_F(PK11Test, MissingKeyfile)
{
  setenv("SIMPLE_TPM_PK11_CONFIG", "testdata/pk11.missingkeyfile.config", 1);
  setenv("SIMPLE_TPM_PK11_LOG_STDERR", "on", 1);
  CK_SESSION_HANDLE s;
  ASSERT_EQ(CKR_OK, func_->C_OpenSession(0, 0, nullptr, nullptr, &s));

  CK_MECHANISM mech = {
    CKM_RSA_PKCS, NULL_PTR, 0
  };

  CK_OBJECT_HANDLE key = 0;
  // TODO: Get first key.

  CK_BYTE data[35];
  CK_BYTE signature[20];
  CK_ULONG slen;
  ASSERT_EQ(CKR_OK, func_->C_SignInit(s, &mech, key));
  ASSERT_EQ(CKR_GENERAL_ERROR, func_->C_Sign(s, data, sizeof(data), signature, &slen));
  EXPECT_NE(std::string::npos, cs.stderr().find("Failed to open key file 'testdata/missing-file'"));
}

TEST_F(PK11Test, BadKeyfile)
{
  setenv("SIMPLE_TPM_PK11_CONFIG", "testdata/pk11.badkeyfile.config", 1);
  setenv("SIMPLE_TPM_PK11_LOG_STDERR", "on", 1);
  CK_SESSION_HANDLE s;
  ASSERT_EQ(CKR_OK, func_->C_OpenSession(0, 0, nullptr, nullptr, &s));

  CK_MECHANISM mech = {
    CKM_RSA_PKCS, NULL_PTR, 0
  };

  CK_OBJECT_HANDLE key = 0;
  // TODO: Get first key.

  CK_BYTE data[35];
  CK_BYTE signature[20];
  CK_ULONG slen;
  ASSERT_EQ(CKR_OK, func_->C_SignInit(s, &mech, key));
  ASSERT_EQ(CKR_FUNCTION_FAILED, func_->C_Sign(s, data, sizeof(data), signature, &slen));
  EXPECT_NE(std::string::npos, cs.stderr().find("Keyfile format error"));
}

TEST_F(PK11Test, AbsKeyfile)
{
  setenv("SIMPLE_TPM_PK11_CONFIG", "testdata/pk11.abskeyfile.config", 1);
  setenv("SIMPLE_TPM_PK11_LOG_STDERR", "on", 1);
  CK_SESSION_HANDLE s;
  ASSERT_EQ(CKR_OK, func_->C_OpenSession(0, 0, nullptr, nullptr, &s));

  CK_MECHANISM mech = {
    CKM_RSA_PKCS, NULL_PTR, 0
  };

  CK_OBJECT_HANDLE key = 0;
  // TODO: Get first key.

  CK_BYTE data[35];
  CK_BYTE signature[20];
  CK_ULONG slen;
  ASSERT_EQ(CKR_OK, func_->C_SignInit(s, &mech, key));
  ASSERT_EQ(CKR_FUNCTION_FAILED, func_->C_Sign(s, data, sizeof(data), signature, &slen));
  EXPECT_NE(std::string::npos, cs.stderr().find("Keyfile incomplete"));
}

TEST_F(PK11Test, Sign)
{
  // TODO: actually test correct output.
  CK_SESSION_HANDLE s;
  ASSERT_EQ(CKR_OK, func_->C_OpenSession(0, 0, nullptr, nullptr, &s));

  CK_MECHANISM mech = {
    CKM_RSA_PKCS, NULL_PTR, 0
  };

  CK_OBJECT_HANDLE key = 0;
  // TODO: Get first key.

  CK_BYTE data[35];
  CK_BYTE signature[20];
  CK_ULONG slen;
  ASSERT_EQ(CKR_OK, func_->C_SignInit(s, &mech, key));
  ASSERT_EQ(CKR_OK, func_->C_Sign(s, data, sizeof(data), signature, &slen));
  ASSERT_EQ(CKR_OK, func_->C_CloseSession(s));
}
