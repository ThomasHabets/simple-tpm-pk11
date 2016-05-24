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
#include"config.h"
#include"gtest/gtest.h"

#include"test_util.h"

extern std::string argv0base;

static void
reset_getopt()
{
#if HAVE_DECL_OPTRESET
  optreset = 1;
#endif
  optind = 1;
}

namespace fake_tspi_data {
  extern int keysize;
}

extern int wrapped_main(int, char**);

TEST(Usage, NoOpts)
{
  argv0base = "foobinary";
  CaptureStreams s;
  reset_getopt();
  char *argv[] = {
    (char*)"keygen",
    NULL,
  };
  EXPECT_EQ(1, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_TRUE(s.stdout().find("\nUsage: ") != std::string::npos);
  EXPECT_EQ("foobinary: Empty output file name.\n", s.stderr());
  EXPECT_EQ("", s.stdlog());
}

TEST(Usage, HelpOpts)
{
  CaptureStreams s;
  reset_getopt();
  char *argv[] = {
    (char*)"keygen",
    (char*)"-h",
    NULL,
  };
  EXPECT_EQ(0, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_TRUE(s.stdout().find("\nUsage: ") != std::string::npos);
  EXPECT_EQ("", s.stderr());
  EXPECT_EQ("", s.stdlog());
}

TEST(Keygen, EmptyOutputName)
{
  argv0base = "foobinary";
  CaptureStreams s;
  reset_getopt();
  char *argv[] = {
    (char*)"keygen",
    (char*)"-o",
    (char*)"",
    NULL,
  };
  EXPECT_EQ(1, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_TRUE(s.stdout().find("\nUsage: ") != std::string::npos);
  EXPECT_EQ("foobinary: Empty output file name.\n", s.stderr());
  EXPECT_EQ("", s.stdlog());
}

TEST(Keygen, BadOutputName)
{
  CaptureStreams s;
  reset_getopt();
  char *argv[] = {
    (char*)"keygen",
    (char*)"-o",
    (char*)"/non/existing/file/here/3ht.sn,hsn",
    NULL,
  };
  EXPECT_EQ(1, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("", s.stdout());
  EXPECT_EQ("Unable to open '/non/existing/file/here/3ht.sn,hsn':"
            " No such file or directory\n", s.stderr());
  EXPECT_EQ("Modulus size: 10\nExponent size: 10\nSize: 2048\nBlob size: 10\n",
            s.stdlog());
}

TEST(Keygen, OK)
{
  CaptureStreams s;
  reset_getopt();
  char *argv[] = {
    (char*)"keygen",
    (char*)"-o",
    (char*)"/dev/null",
    NULL,
  };
  EXPECT_EQ(0, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("", s.stdout());
  EXPECT_EQ("", s.stderr());
  EXPECT_EQ("Modulus size: 10\nExponent size: 10\nSize: 2048\nBlob size: 10\n",
            s.stdlog());
}

TEST(Keygen, SWKeyOK)
{
  CaptureStreams s;
  reset_getopt();
  char *argv[] = {
    (char*)"keygen",
    (char*)"-S",
    (char*)"-o",
    (char*)"/dev/null",
    NULL,
  };
  EXPECT_EQ(0, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("", s.stdout());
  EXPECT_EQ("", s.stderr());
  EXPECT_EQ("", s.stdlog());
}

TEST(Keygen, SmallerKey)
{
  CaptureStreams s;
  reset_getopt();
  char *argv[] = {
    (char*)"keygen",
    (char*)"-b",
    (char*)"1024",
    (char*)"-o",
    (char*)"/dev/null",
    NULL,
  };
  fake_tspi_data::keysize = 1024;
  EXPECT_EQ(0, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("", s.stdout());
  EXPECT_EQ("", s.stderr());
  EXPECT_EQ("Modulus size: 10\nExponent size: 10\nSize: 1024\nBlob size: 10\n",
            s.stdlog());
}

TEST(Keygen, WrongTPMKeySize)
{
  CaptureStreams s;
  reset_getopt();
  char *argv[] = {
    (char*)"keygen",
    (char*)"-b",
    (char*)"1024",
    (char*)"-o",
    (char*)"/dev/null",
    NULL,
  };
  fake_tspi_data::keysize = 2048;
  EXPECT_THROW(wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv),
               std::exception);
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
