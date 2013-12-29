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
#include<cstdio>
#include<fstream>
#include<iomanip>
#include<iostream>
#include<iterator>
#include<sstream>
#include<string>
#include<unistd.h>

#include"tss/tspi.h"

#include"common.h"
#include"internal.h"

extern std::string argv0base;


BEGIN_NAMESPACE();
int
usage(int rc)
{
  std::cout << "Usage: " << argv0base << " [ -hs ] -f <data> -k <keyfile>\n"
            << "    -f <data file>    File to sign.\n"
            << "    -h, --help        Show this help text.\n"
            << "    -k <keyfile>      File containing key data.\n"
            << "    -s                Prompt for SRK password/PIN.\n";
  return rc;
}
END_NAMESPACE();

int
wrapped_main(int argc, char **argv)
{
  int c;
  std::string keyfile;
  std::string signfile;
  bool set_srk_pin{false};
  bool set_key_pin{false};
  while (EOF != (c = getopt(argc, argv, "hk:f:s"))) {
    switch (c) {
    case 'h':
      return usage(0);
    case 'k':
      keyfile = optarg;
      break;
    case 's':
      set_srk_pin = true;
      break;
    case 'f':
      signfile = optarg;
      break;
    default:
      return usage(1);
    }
  }
  if (keyfile.empty() || signfile.empty()) {
    std::cerr << "stpm-sign: Need to specify keyfile and data file"
              << std::endl;
    return usage(1);
  }
  std::ifstream kf(keyfile);
  if (!kf) {
    std::cerr << "stpm-sign: Can't open keyfile '" << keyfile << "'\n";
    return usage(1);
  }
  std::string kfs{std::istreambuf_iterator<char>(kf),
                  std::istreambuf_iterator<char>()};
  std::ifstream sf(signfile);
  if (!sf) {
    std::cerr << "stpm-sign: Can't open file '" << signfile << "'\n";
    return usage(1);
  }
  std::string sfs{std::istreambuf_iterator<char>(sf),
                  std::istreambuf_iterator<char>()};
  auto key = stpm::parse_keyfile(kfs);
  std::string srk_pin;
  if (set_srk_pin) {
    // TODO: read from terminal without echo.
    std::cerr << "Enter SRK PIN: " << std::flush;
    getline(std::cin, srk_pin);
  }

  if (stpm::auth_required(set_srk_pin ? &srk_pin : NULL,
                          key)) {
    set_key_pin = true;
  }

  std::string key_pin;
  if (set_key_pin) {
    // TODO: read from terminal without echo.
    std::cerr << "Enter key PIN: " << std::flush;
    getline(std::cin, key_pin);
  }
  std::cout << "Loaded key: " << key << std::endl
            << "--- Signature ---\n"
            << stpm::to_hex(sign(key, sfs,
                                 set_srk_pin ? &srk_pin : NULL,
                                 set_key_pin ? &key_pin : NULL)) << std::endl;
  return 0;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
