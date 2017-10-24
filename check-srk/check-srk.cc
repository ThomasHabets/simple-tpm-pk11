/**
 * Copyright 2017 Google Inc. All Rights Reserved.
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
/*
 * Ugly hack to extract the SRK modulus to then check for Infineon disaster vuln.
 *
 * Compile with: g++ -o check-srk -std=gnu++11 check-srk.cc -ltspi -lssl -lcrypto
 *
 */
#include<cstdio>
#include<cstdlib>
#include<cstring>
#include<iostream>
#include<unistd.h>
#include<set>
#include<vector>

#include<openssl/bn.h>
#include<tss/tspi.h>
#include<trousers/trousers.h>

std::vector<std::pair<int, std::set<int>>> tests;

void
init_tests()
{
  tests.push_back(std::pair<int, std::set<int>>(11, {1, 10}));
  tests.push_back(std::pair<int, std::set<int>>(13, {1, 3, 4, 9, 10, 12}));
  tests.push_back(std::pair<int, std::set<int>>(17, {1, 2, 4, 8, 9, 13, 15, 16}));
  tests.push_back(std::pair<int, std::set<int>>(19, {1, 4, 5, 6, 7, 9, 11, 16, 17}));
  tests.push_back(std::pair<int, std::set<int>>(37, {1, 10, 26}));
  tests.push_back(std::pair<int, std::set<int>>(53, {1, 4, 6, 7, 9, 10, 11, 13, 15, 16, 17, 24, 25, 28, 29, 36, 37, 38, 40, 42, 43, 44, 46, 47, 49, 52}));
  tests.push_back(std::pair<int, std::set<int>>(61, {1, 34, 3, 37, 38, 33, 8, 9, 11, 60, 50, 20, 41, 23, 24, 52, 58, 27, 28, 53}));
  tests.push_back(std::pair<int, std::set<int>>(71, {1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 15, 16, 18, 19, 20, 24, 25, 27, 29, 30, 32, 36, 37, 38, 40, 43, 45, 48, 49, 50, 54, 57, 58, 60, 64}));
  tests.push_back(std::pair<int, std::set<int>>(73, {1, 3, 7, 8, 9, 10, 17, 21, 22, 24, 27, 30, 43, 46, 49, 51, 52, 56, 63, 64, 65, 66, 70, 72}));
  tests.push_back(std::pair<int, std::set<int>>(79, {64, 1, 67, 38, 65, 8, 10, 46, 18, 52, 21, 22, 62}));
  tests.push_back(std::pair<int, std::set<int>>(97, {96, 1, 35, 36, 61, 62}));
  tests.push_back(std::pair<int, std::set<int>>(103, {1, 2, 4, 7, 8, 9, 13, 14, 15, 16, 17, 18, 19, 23, 25, 26, 28, 29, 30, 32, 33, 34, 36, 38, 41, 46, 49, 50, 52, 55, 56, 58, 59, 60, 61, 63, 64, 66, 68, 72, 76, 79, 81, 82, 83, 91, 92, 93, 97, 98, 100}));
  tests.push_back(std::pair<int, std::set<int>>(107, {1, 3, 4, 9, 10, 11, 12, 13, 14, 16, 19, 23, 25, 27, 29, 30, 33, 34, 35, 36, 37, 39, 40, 41, 42, 44, 47, 48, 49, 52, 53, 56, 57, 61, 62, 64, 69, 75, 76, 79, 81, 83, 85, 86, 87, 89, 90, 92, 99, 100, 101, 102, 105}));
  tests.push_back(std::pair<int, std::set<int>>(109, {1, 3, 4, 5, 7, 9, 12, 15, 16, 20, 21, 22, 25, 26, 27, 28, 29, 31, 34, 35, 36, 38, 43, 45, 46, 48, 49, 60, 61, 63, 64, 66, 71, 73, 74, 75, 78, 80, 81, 82, 83, 84, 87, 88, 89, 93, 94, 97, 100, 102, 104, 105, 106, 108}));
  tests.push_back(std::pair<int, std::set<int>>(127, {1, 2, 4, 5, 8, 10, 16, 19, 20, 25, 27, 32, 33, 38, 40, 47, 50, 51, 54, 61, 63, 64, 66, 73, 76, 77, 80, 87, 89, 94, 95, 100, 102, 107, 108, 111, 117, 119, 122, 123, 125, 126}));
  tests.push_back(std::pair<int, std::set<int>>(151, {1, 3, 132, 8, 9, 142, 143, 19, 20, 150, 24, 26, 27, 28, 29, 41, 44, 50, 53, 57, 59, 60, 64, 65, 67, 68, 70, 72, 73, 78, 79, 81, 83, 84, 86, 87, 91, 92, 94, 98, 131, 101, 107, 110, 148, 122, 123, 124, 125, 127}));
  tests.push_back(std::pair<int, std::set<int>>(157, {1, 130, 3, 4, 9, 10, 11, 12, 13, 14, 143, 16, 17, 146, 19, 148, 153, 25, 154, 27, 156, 30, 31, 33, 35, 36, 37, 39, 40, 42, 44, 46, 47, 48, 49, 51, 52, 56, 57, 58, 138, 64, 67, 68, 71, 140, 75, 76, 141, 81, 82, 147, 86, 89, 90, 93, 144, 99, 100, 101, 145, 105, 106, 108, 109, 110, 111, 113, 115, 117, 118, 132, 120, 121, 122, 124, 126, 127}));
}

bool
is_vuln(BIGNUM* modulus) {
  auto ctx = BN_CTX_new();

  auto m = BN_new();
  auto s = BN_new();
  auto z = BN_new();
  for (const auto ms : tests) {
    BN_dec2bn(&m, std::to_string(ms.first).c_str());
    BN_mod(z, modulus, m, ctx);
    const std::string lhs = BN_bn2dec(z);
    char* end;
    auto n = strtoul(lhs.c_str(), &end, 10);
    if (*end) {
      std::cerr << "internal errz\n";
      exit(1);
    }
    if (!ms.second.count(n)) {
      return false;
    }
  }
  return true;
}

// NULL for WKS.
const char* srk_pin = NULL;

int
main(int argc, char** argv)
{
  init_tests();
  int opt;
  while ((opt = getopt(argc, argv, "s:")) != -1) {
    switch (opt) {
    case 's':
      srk_pin = optarg;
      break;
    default:
      fprintf(stderr, "Usage: %s [-s <SRK pin>]\n", argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  TSS_HCONTEXT ctx;
  if (TSS_SUCCESS != Tspi_Context_Create(&ctx)) {
    fprintf(stderr, "Failed to create context\n");
    exit(1);
  }
  if (TSS_SUCCESS != Tspi_Context_Connect(ctx, NULL)) {
    fprintf(stderr, "Failed to connect context\n");
    exit(1);
  }

  TSS_HTPM tpm;
  TSS_RESULT res = Tspi_Context_GetTpmObject(ctx, &tpm);
  if (TSS_SUCCESS != res) {
    fprintf(stderr, "Failed to get TPM object: %d %x\n", res, res);
    exit(1);
  }

  TSS_HKEY key;
  TSS_HPOLICY policy;
  res = Tspi_Context_CreateObject(ctx,
                                  TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_TSP_SRK, &key);
  if (TSS_SUCCESS != res) {
    fprintf(stderr, "Failed to create SRK object: %d %x\n", res, res);
    exit(1);
  }

  res = Tspi_Context_LoadKeyByUUID(
      ctx,
      TSS_PS_TYPE_SYSTEM,
      TSS_UUID_SRK,
      &key);
  if (TSS_SUCCESS != res) {
    fprintf(stderr, "Failed to load SRK key: %x\n", res);
    exit(1);
  }

  res = Tspi_Context_CreateObject(ctx,
                                 TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &policy);

  if (TSS_SUCCESS != res) {
    fprintf(stderr, "Failed to create policy: %d %x\n", res, res);
    exit(1);
  }

  // Set up SRK PIN.
  if (!srk_pin){
    BYTE wks[] = TSS_WELL_KNOWN_SECRET;
    int wks_size = sizeof(wks);
    res = Tspi_Policy_SetSecret(policy,
                                TSS_SECRET_MODE_SHA1, wks_size, wks);
    if (TSS_SUCCESS != res) {
      fprintf(stderr, "Failed to set WKS: %d %x\n", res, res);
      exit(1);
    }
  } else {
    res = Tspi_Policy_SetSecret(policy, TSS_SECRET_MODE_PLAIN, strlen(srk_pin),(BYTE*)srk_pin);
    if (TSS_SUCCESS != res) {
      fprintf(stderr, "Failed to set WKS: %d %x\n", res, res);
      exit(1);
    }
  }

  res = Tspi_Policy_AssignToObject(policy, key);
  if (TSS_SUCCESS != res) {
    fprintf(stderr, "Failed to assign policy to key: %d %x\n", res, res);
    exit(1);
  }

  // Get size.
  {
    UINT32 size;
    res = Tspi_GetAttribUint32(
        key,
        TSS_TSPATTRIB_RSAKEY_INFO, TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
        &size);
    if (TSS_SUCCESS != res) {
      fprintf(stderr, "Failed to get length of SRK: %d %x\n", res, res);
      exit(1);
    }
    std::clog << "Size: " << size << std::endl;
  }

  if (true) {
    // TODO: I don't know why I have to GetPubKey before GetAttribData,
    // but apparently I do.
    BYTE *srk_pub;
    UINT32 srk_pub_len = 0;
    res = Tspi_Key_GetPubKey(key, &srk_pub_len, &srk_pub);
    if (TSS_SUCCESS != res) {
      fprintf(stderr,
              "Failed to SRK pubkey: %x\n"
              "Maybe you have an SRK PIN you need to supply with -s?\n", res);
      exit(1);
    }
  }

  // Get modulus.
  {
    BYTE* m;
    UINT32 m_size = 0;
    res = Tspi_GetAttribData(
        key, TSS_TSPATTRIB_RSAKEY_INFO,
        TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
        &m_size, &m);
    if (TPM_ERROR(res)) {
      fprintf(stderr, "Failed to get SRK modulus: %x\n", res);
      exit(1);
    }
    auto mod = BN_new();
    if (!BN_bin2bn(m, m_size, mod)) {
      fprintf(stderr, "BN_bin2bn failed\n");
      exit(1);
    }
    std::clog << "Outputting modulus…\n";
    printf("%s\n", BN_bn2dec(mod));
    if (is_vuln(mod)) {
      std::cerr << "--------------\nTHE KEY IS WEAK!\n";
    } else {
      std::cerr << "--------------\nThe key is fine.\n";
    }
  }
}
