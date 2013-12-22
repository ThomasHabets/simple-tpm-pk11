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
#include<iostream>
#include<libgen.h>
#include<string>

#include"common.h"

extern int wrapped_main(int argc, char **argv);

int
main(int argc, char **argv)
{
  const std::string prefix = basename(argv[0]);
  try {
    return wrapped_main(argc, argv);
  } catch (const stpm::TSPIException& e) {
    std::cerr << prefix << ": Exception:\n  " << e.what() << std::endl;
    if (!e.extra().empty()) {
      std::cerr << e.extra() << std::endl;
    }
  } catch (const std::exception& e) {
    std::cerr << prefix << ": Exception: " << e.what() << std::endl;
  } catch (...) {
    // Shouldn't happen.
    std::cerr << prefix << ": Exception of unknown type!\n";
  }
  return 1;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
