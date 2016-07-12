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
 *
 * TODO: Add more tests.
 */
#include"config.h"
#include<stdexcept>
#include"gtest/gtest.h"

#include"test_util.h"

static void
reset_getopt()
{
#if HAVE_DECL_OPTRESET
  optreset = 1;
#endif
  optind = 1;
}

extern int wrapped_main(int, char**);

TEST(Usage, NoOpts)
{
  CaptureStreams s;
  reset_getopt();
  char *argv[] = {
    (char*)"sign",
    NULL,
  };
  EXPECT_EQ(1, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_TRUE(s.stdout().find("\nUsage: ") != std::string::npos);
  EXPECT_EQ("test-binary: Need to specify keyfile, data file, and signature file.\n", s.stderr());
  EXPECT_EQ("", s.stdlog());
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
