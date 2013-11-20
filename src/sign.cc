#include<cstdio>
#include<fstream>
#include<iomanip>
#include<iostream>
#include<iterator>
#include<sstream>
#include<string>
#include<tuple>
#include<unistd.h>

#include"tss/tspi.h"

#include"common.h"
#include"internal.h"

BEGIN_NAMESPACE();
void
usage(int rc)
{
  std::cout << "Usage: sign [ -h ] -k <keyfile> -f <data>" << std::endl;
  exit(rc);
}
END_NAMESPACE();

int
wrapped_main(int argc, char **argv)
{
  int c;
  std::string keyfile;
  std::string signfile;
  while (EOF != (c = getopt(argc, argv, "hk:f:"))) {
    switch (c) {
    case 'h':
      usage(0);
    case 'k':
      keyfile = optarg;
      break;
    case 'f':
      signfile = optarg;
      break;
    default:
      usage(1);
    }
  }
  if (keyfile.empty() || signfile.empty()) {
    usage(1);
  }
  std::ifstream kf(keyfile);
  std::string kfs{std::istreambuf_iterator<char>(kf),
      std::istreambuf_iterator<char>()};
  std::ifstream sf(signfile);
  std::string sfs{std::istreambuf_iterator<char>(sf),
      std::istreambuf_iterator<char>()};
  auto key = stpm::parse_keyfile(kfs);
  std::cout << "Loaded key: " << key << std::endl
            << "=== Signature ===\n"
            << stpm::to_hex(sign(key, sfs)) << std::endl;
  return 0;
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
