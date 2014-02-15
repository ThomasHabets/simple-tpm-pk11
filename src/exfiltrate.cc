/**
 * Copyright 2014 Google Inc. All Rights Reserved.
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
#include<string>
#include<iostream>
#include<unistd.h>

#include"common.h"
#include"internal.h"

extern std::string argv0base;

BEGIN_NAMESPACE();
int
usage(int rc)
{
  std::cout << "Usage: " << argv0base << " [ -hsOp ] -k <key file>\n"
            << "    -h, --help     Show this help text.\n"
            << "    -k <key file>  Key file.\n"
            << "    -O             Use Well Known Secret for owner password. Default is ask.\n"
            << "    -p             Ask for key password/PIN. Default is Well Known Secret.\n"
            << "    -s             Ask for SRK password/PIN. Default is Well Known Secret.\n";
  return rc;
}
END_NAMESPACE();

int
wrapped_main(int argc, char **argv)
{
  bool set_srk_pin = false;
  bool set_key_pin = false;
  bool set_owner_pin = true;
  std::string srk_pin;
  std::string key_pin;
  std::string owner;
  std::string keyfile;
  int c;

  while (EOF != (c = getopt(argc, argv, "hk:Ops"))) {
    switch (c) {
    case 'h':
      return usage(0);
    case 'k':
      keyfile = optarg;
      break;
    case 's':
      set_srk_pin = true;
      break;
    case 'p':
      set_key_pin = true;
      break;
    case 'O':
      set_owner_pin = false;
      break;
    default:
      return usage(1);
    }
  }

  if (keyfile.empty()) {
    std::cerr << argv0base << ": Empty key file name." << std::endl;
    return usage(1);
  }

  if (set_owner_pin) {
    owner = stpm::xgetpass("Enter owner password");
  }

  if (set_key_pin) {
    key_pin = stpm::xgetpass("Enter key password");
  }

  if (set_srk_pin) {
    srk_pin = stpm::xgetpass("Enter SRK password");
  }

  const auto key = stpm::parse_keyfile(stpm::slurp_file(keyfile));
  const auto sw = stpm::exfiltrate_key(key,
                                       set_srk_pin ? &srk_pin : nullptr,
                                       owner,
                                       set_key_pin ? &key_pin : nullptr);
  std::cout << sw << std::endl;
  return 0;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
