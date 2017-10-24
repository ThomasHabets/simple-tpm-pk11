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
 * Compile with:
 *    g++ -o check-srk -std=gnu++11 check-srk.cc -ltspi -lssl -lcrypto
 *
 */
#include<cstdio>
#include<cmath>
#include<cstdlib>
#include<cstring>
#include<iostream>
#include<unistd.h>
#include<set>
#include<vector>

#include<openssl/bn.h>
#include<tss/tspi.h>
#include<trousers/trousers.h>

#include"../src/common.h"

std::vector<std::pair<int, std::set<int>>>
make_tests()
{
  // Credit: https://crypto.stackexchange.com/questions/52292/what-is-fast-prime
  const std::vector<std::pair<int, int>> generators = {
    {2, 11},
    {6, 13},
    {8, 17},
    {9, 19},
    {3, 37},
    {26, 53},
    {20, 61},
    {35, 71},
    {24, 73},
    {13, 79},
    {6, 97},
    {51, 103},
    {53, 107},
    {54, 109},
    {42, 127},
    {50, 151},
    {78, 157},
  };

  stpm::BNCTXWrap ctx;
  std::vector<std::pair<int, std::set<int>>> ret;
  for (const auto& g : generators) {
    stpm::BIGNUMWrap r, p, res, i;

    BN_dec2bn(r.getp(), std::to_string(g.first).c_str());
    BN_dec2bn(p.getp(), std::to_string(g.second).c_str());

    std::set<int> l;
    for (int c = 0; c < g.second; c++) {
      BN_dec2bn(i.getp(), std::to_string(c).c_str());
      BN_mod_exp(res.get(), i.get(), r.get(), p.get(), ctx.get());
      if (!strcmp(BN_bn2dec(res.get()), "1")) {
        l.insert(c);
      }
    }
    ret.push_back({g.second, l});
  }
  return ret;
}

const std::vector<std::pair<int, std::set<int>>> tests = make_tests();

bool
is_vuln(BIGNUM* modulus) {
  stpm::BNCTXWrap ctx;

  stpm::BIGNUMWrap m, s, z;
  for (const auto ms : tests) {
    BN_dec2bn(m.getp(), std::to_string(ms.first).c_str());
    BN_mod(z.get(), modulus, m.get(), ctx.get());
    const std::string lhs = BN_bn2dec(z.get());
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

void
self_test()
{
  std::clog << "Running self test…\n";
  const std::string bad =
    "19938056020098197365562045602452702481764029031788901515041637346"
    "59664301810397435517958505193657308878577182396178388805949567514"
    "93072326478239626428117453688560571382508192163477482599263238431"
    "23409832353911425474214399357279154291350609095053100959029512111"
    "18843523882986697836910369306226827544922081786889434456105668874"
    "75559631105557876688469588507548413520336914672788668741683050708"
    "52577071087674316932650955818705357676526040250814850835930967219"
    "87657456512408680098709248942496286520609642408378616866232460847"
    "82246097027454407148731567090590896088004920146482353728837014129"
    "47627934562329911019602948939463";
  const std::string good =
    "10370958248394357517927560885830722492008924663624587591822132987"
    "96780013019139759397453360064558094368183834718579254844745074698"
    "14152191546180006061001646994710489151933960477358446164968530575"
    "65033770341665769755559091048068263979924104921646738915200262650"
    "78651948163902522767455462804827862036592643288146195217828089952"
    "88806167443550955372809448344660673102522500801426337516136781403"
    "92439851732672531048042240879559796179184971260687770238899126397"
    "90153991157220986800506575923567680693759749035973704825051373788"
    "95095946104093984893324803391764381923945603803100327231565213476"
    "35531022883252286505870258531927";

  stpm::BIGNUMWrap m;
  BN_dec2bn(m.getp(), good.c_str());
  if (is_vuln(m.get())) {
    std::cerr << "Internal self test error: Known good was detected as bad\n";
    exit(1);
  }

  BN_dec2bn(m.getp(), bad.c_str());
  if (!is_vuln(m.get())) {
    std::cerr << "Internal self test error: Known bad was detected as good\n";
    exit(1);
  }
}

int
main(int argc, char** argv)
{
  self_test();

  // NULL for WKS.
  const char* srk_pin = NULL;
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
    stpm::BIGNUMWrap mod;
    if (!BN_bin2bn(m, m_size, mod.get())) {
      std::cerr << "BN_bin2bn failed\n";
      exit(1);
    }
    std::clog << "Modulus:\n";
    std::cout << BN_bn2dec(mod.get()) << std::endl;
    if (is_vuln(mod.get())) {
      std::cerr << "--------------\nTHE KEY IS WEAK!\n";
    } else {
      std::cerr << "--------------\nThe key is fine.\n";
    }
  }
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
