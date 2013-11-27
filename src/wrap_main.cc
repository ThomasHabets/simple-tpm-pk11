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
#include<string>

extern int wrapped_main(int argc, char **argv);

int
main(int argc, char **argv)
{
  try {
    return wrapped_main(argc, argv);
  } catch (const std::string& msg) {
    std::cerr << "Exception: " << msg << std::endl;
  } catch (const char *msg) {
    std::cerr << "Exception: " << msg << std::endl;
  } catch (...) {
    std::cerr << "Exception of unknown type!\n";
  }
  return 1;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
