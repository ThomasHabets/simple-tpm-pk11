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

#include"common.h"

int
wrapped_main(int argc, char **argv)
{
  bool set_srk_pin = false;
  bool set_key_pin = false;
  std::string srk_pin = "";
  std::string key_pin = "";
  std::string owner;

  if (true) {
    std::cerr << "Enter owner password: " << std::flush;
    getline(std::cin, owner);
  }

  const auto key = stpm::parse_keyfile(stpm::slurp_file("foo.key"));
  const auto sw = stpm::exfiltrate_key(key,
				       set_srk_pin ? &srk_pin : nullptr,
				       owner,
				       set_key_pin ? &key_pin : nullptr);
  std::cout << sw << std::endl;
  return 0;
}
