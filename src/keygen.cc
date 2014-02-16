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
// Key generator main().
#ifdef HAVE_CONFIG_H
#include"config.h"
#endif

#include<cstring>
#include<cstdlib>
#include<fstream>
#include<iostream>
#include<unistd.h>

#include"common.h"
#include"internal.h"

extern std::string argv0base;

BEGIN_NAMESPACE();
int
usage(int rc)
{
  std::cout << PACKAGE_STRING << std::endl
            << "Usage: " << argv0base << " [ -hsSp ] [ -b <bits> ] -o <output file>\n"
            << "    -b <bits>         Key size in bits. TPM chips tend to support up to 2048.\n"
            << "    -h, --help        Show this help text.\n"
            << "    -o <output file>  Output file to store the key information in.\n"
            << "    -p                Set a password/PIN on the generated key.\n"
            << "    -s                Ask for SRK password/PIN. Default is Well Known Secret.\n"
            << "    -S                Generate the key in software (see manpage).\n";
  return rc;
}
END_NAMESPACE();

int
wrapped_main(int argc, char **argv)
{
  int c;
  std::string output;
  bool set_srk_pin{false};
  bool set_key_pin{false};
  int bits = 2048;
  bool software{false};

  while (EOF != (c = getopt(argc, argv, "b:ho:sSp"))) {
    switch (c) {
    case 'b':
      bits = std::stoi(optarg);
      break;
    case 'h':
      return usage(0);
    case 's':
      set_srk_pin = true;
      break;
    case 'S':
      software = true;
      break;
    case 'p':
      set_key_pin = true;
      break;
    case 'o':
      output = optarg;
      break;
    default:
      return usage(1);
    }
  }
  if (output.empty()) {
    std::cerr << argv0base << ": Empty output file name." << std::endl;
    return usage(1);
  }

  std::string srk_pin;
  if (set_srk_pin) {
    srk_pin = stpm::xgetpass("Enter SRK PIN");
  }

  std::string key_pin;
  if (set_key_pin) {
    key_pin = stpm::xgetpass("Enter key PIN");
  }
  stpm::Key key;
  if (software) {
    const auto sw = stpm::generate_software_key(bits);
    key = stpm::wrap_key(set_srk_pin ? &srk_pin : nullptr,
                         set_key_pin ? &key_pin : nullptr,
                         sw);
  } else {
    key = stpm::generate_key(set_srk_pin ? &srk_pin : nullptr,
                             set_key_pin ? &key_pin : nullptr,
                             bits);
  }
  std::ofstream fo(output);
  if (!fo) {
    std::cerr << "Unable to open '" << output << "': "
              << strerror(errno) << std::endl;
    return 1;
  }
  fo << "# Some sort of key.\n"
     << "# Key was generated in " << (software ? "software.\n" : "hardware.\n")
     << "exp " << stpm::to_hex(key.exponent) << std::endl
     << "mod " << stpm::to_hex(key.modulus) << std::endl
     << "blob " << stpm::to_hex(key.blob) << std::endl;
  return 0;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
