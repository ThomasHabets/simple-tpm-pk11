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
 * Take output modulus and shove it into https://gist.github.com/marcan/fc87aa78085c2b6f979aefc73fdc381f
 */
#include<cstdio>
#include<cstdlib>
#include<cstring>
#include<iostream>
#include<unistd.h>

#include<openssl/bn.h>
#include<tss/tspi.h>
#include<trousers/trousers.h>

// NULL for WKS.
const char* srk_pin = NULL;

int
main(int argc, char** argv)
{
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
  }
}
