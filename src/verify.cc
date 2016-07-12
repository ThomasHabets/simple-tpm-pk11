/**
 * Copyright 2016 Google Inc. All Rights Reserved.
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
#ifdef HAVE_CONFIG_H
#include"config.h"
#endif
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
  std::cout << PACKAGE_STRING << std::endl
            << "Usage: " << argv0base
            << " [ -hq ] -f <data> -s <sig file> -k <keyfile>\n"
            << "    -f <data file>    File to verify.\n"
            << "    -s <sig file>     File containing signature.\n"
            << "    -h, --help        Show this help text.\n"
            << "    -k <keyfile>      File containing key data.\n"
            << "    -q                Don't output any messages.\n";
  return rc;
}
END_NAMESPACE();

int
wrapped_main(int argc, char **argv)
{
  int c;
  std::string keyfile;
  std::string signfile;
  std::string signaturefile;
  bool quiet{false};
  while (EOF != (c = getopt(argc, argv, "hk:f:s:q"))) {
    switch (c) {
    case 'h':
      return usage(0);
    case 'k':
      keyfile = optarg;
      break;
    case 'f':
      signfile = optarg;
      break;
    case 's':
      signaturefile = optarg;
      break;
    case 'q':
      quiet = true;
      break;
    default:
      return usage(1);
    }
  }
  if (optind != argc) {
    std::cerr << argv0base << ": Extra non-option args not allowed.\n";
    return usage(1);
  }
  if (keyfile.empty() || signfile.empty() || signaturefile.empty()) {
    std::cerr << argv0base
              << ": Need to specify keyfile, data file, and signature file."
              << std::endl;
    return usage(1);
  }

  const auto key = stpm::parse_keyfile(stpm::slurp_file(keyfile));
  const auto to_sign = stpm::slurp_file(signfile);
  const auto signature = stpm::slurp_file(signaturefile);
  if (!verify(key, to_sign, signature)) {
    if (!quiet) {
      std::cout << "fail\n";
    }
    return 1;
  }
  if (!quiet) {
    std::cout << "success\n";
  }
  return 0;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
