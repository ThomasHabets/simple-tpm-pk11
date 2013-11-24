#include "gtest/gtest.h"

#include "test_util.h"

extern int wrapped_main(int, char**);

TEST(Usage, NoOpts)
{
  CaptureStreams s;
  optind = 0;
  char *argv[] = {
    (char*)"sign",
    NULL,
  };
  EXPECT_EQ(1, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("Usage: ", s.stdout().substr(0, 7));
  EXPECT_EQ("stpm-sign: Need to specify keyfile and data file\n", s.stderr());
  EXPECT_EQ("", s.stdlog());
}

TEST(Sign, NoDataFile)
{
  CaptureStreams s;
  optind = 0;
  char *argv[] = {
    (char*)"sign",
    (char*)"-k",
    (char*)"",
    NULL,
  };
  EXPECT_EQ(1, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("Usage: ", s.stdout().substr(0, 7));
  EXPECT_EQ("stpm-sign: Need to specify keyfile and data file\n", s.stderr());
  EXPECT_EQ("", s.stdlog());
}

TEST(Sign, NoKeyFile)
{
  CaptureStreams s;
  optind = 0;
  char *argv[] = {
    (char*)"sign",
    (char*)"-f",
    (char*)"",
    NULL,
  };
  EXPECT_EQ(1, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("Usage: ", s.stdout().substr(0, 7));
  EXPECT_EQ("stpm-sign: Need to specify keyfile and data file\n", s.stderr());
  EXPECT_EQ("", s.stdlog());
}

TEST(Usage, HelpOpts)
{
  CaptureStreams s;
  optind = 0;
  char *argv[] = {
    (char*)"sign",
    (char*)"-h",
    NULL,
  };
  EXPECT_EQ(0, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("Usage: ", s.stdout().substr(0, 7));
  EXPECT_EQ("", s.stderr());
  EXPECT_EQ("", s.stdlog());
}

TEST(Sign, BadKeyfileName)
{
  CaptureStreams s;
  optind = 0;
  char *argv[] = {
    (char*)"sign",
    (char*)"-k",
    (char*)"/non/existing/file/here/3ht.sn,hsn",
    (char*)"-f",
    (char*)"/dev/null",
    NULL,
  };
  EXPECT_EQ(1, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("Usage: ", s.stdout().substr(0, 7));
  EXPECT_EQ("stpm-sign: Can't open keyfile '/non/existing/file/here/3ht.sn,hsn'\n", s.stderr());
  EXPECT_EQ("", s.stdlog());
}

TEST(Sign, BadDatafileName)
{
  CaptureStreams s;
  optind = 0;
  char *argv[] = {
    (char*)"sign",
    (char*)"-k",
    (char*)"testdata/correct.key",
    (char*)"-f",
    (char*)"/non/existing/file/here/3ht.sn,hsn",
    NULL,
  };
  EXPECT_EQ(1, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("Usage: ", s.stdout().substr(0, 7));
  EXPECT_EQ("stpm-sign: Can't open file '/non/existing/file/here/3ht.sn,hsn'\n", s.stderr());
  EXPECT_EQ("", s.stdlog());
}

TEST(Sign, OK)
{
  CaptureStreams s;
  optind = 0;
  char *argv[] = {
    (char*)"sign",
    (char*)"-k",
    (char*)"testdata/correct.key",
    (char*)"-f",
    (char*)"/dev/null",
    NULL,
  };
  EXPECT_EQ(0, wrapped_main(sizeof(argv)/sizeof(void*) - 1, argv));
  EXPECT_EQ("Loaded key: mod=010203,exp=010001,blob=010203040506\n=== Signature ===\n12345678\n", s.stdout());
  EXPECT_EQ("", s.stderr());
  EXPECT_EQ("", s.stdlog());
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
