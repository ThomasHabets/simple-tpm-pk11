#include "gtest/gtest.h"

#include "test_util.h"

extern int wrapped_main(int, char**);

TEST(Usage, NoOpts)
{
  CaptureStreams s;
  optind = 0;
  char *argv[] = {
    (char*)"keygen",
    NULL,
  };
  EXPECT_EQ(1, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("Usage: ", s.stdout().substr(0, 7));
  EXPECT_EQ("stpm-keygen: Empty output file name.\n", s.stderr());
  EXPECT_EQ("", s.stdlog());
}

TEST(Usage, HelpOpts)
{
  CaptureStreams s;
  optind = 0;
  char *argv[] = {
    (char*)"keygen",
    (char*)"-h",
    NULL,
  };
  EXPECT_EQ(0, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("Usage: ", s.stdout().substr(0, 7));
  EXPECT_EQ("", s.stderr());
  EXPECT_EQ("", s.stdlog());
}

TEST(Keygen, EmptyOutputName)
{
  CaptureStreams s;
  optind = 0;
  char *argv[] = {
    (char*)"keygen",
    (char*)"-o",
    (char*)"",
    NULL,
  };
  EXPECT_EQ(1, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("Usage: ", s.stdout().substr(0, 7));
  EXPECT_EQ("stpm-keygen: Empty output file name.\n", s.stderr());
  EXPECT_EQ("", s.stdlog());
}

TEST(Keygen, BadOutputName)
{
  CaptureStreams s;
  optind = 0;
  char *argv[] = {
    (char*)"keygen",
    (char*)"-o",
    (char*)"/non/existing/file/here/3ht.sn,hsn",
    NULL,
  };
  EXPECT_EQ(1, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("", s.stdout());
  EXPECT_EQ("Unable to open '/non/existing/file/here/3ht.sn,hsn'\n", s.stderr());
  EXPECT_EQ("Modulus size: 10\nExponent size: 10\nSize: 123\nBlob size: 10\n",
            s.stdlog());
}

TEST(Keygen, OK)
{
  CaptureStreams s;
  optind = 0;
  char *argv[] = {
    (char*)"keygen",
    (char*)"-o",
    (char*)"/dev/null",
    NULL,
  };
  EXPECT_EQ(0, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("", s.stdout());
  EXPECT_EQ("", s.stderr());
  EXPECT_EQ("Modulus size: 10\nExponent size: 10\nSize: 123\nBlob size: 10\n",
            s.stdlog());
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
