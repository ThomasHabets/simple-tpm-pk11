#include<cstdio>
#include<fstream>
#include<iomanip>
#include<iostream>
#include<iterator>
#include<sstream>
#include<string>
#include<unistd.h>

#include"tss/tspi.h"

#include"common.h"
#include"internal.h"

BEGIN_NAMESPACE();
int
usage(int rc)
{
  std::cout << "Usage: sign [ -h ] -k <keyfile> -f <data>" << std::endl;
  return rc;
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
      return usage(0);
    case 'k':
      keyfile = optarg;
      break;
    case 'f':
      signfile = optarg;
      break;
    default:
      return usage(1);
    }
  }
  if (keyfile.empty() || signfile.empty()) {
    std::cerr << "stpm-sign: Need to specify keyfile and data file"
              << std::endl;
    return usage(1);
  }
  std::ifstream kf(keyfile);
  if (!kf) {
    std::cerr << "stpm-sign: Can't open keyfile '" << keyfile << "'\n";
    return usage(1);
  }
  std::string kfs{std::istreambuf_iterator<char>(kf),
                  std::istreambuf_iterator<char>()};
  std::ifstream sf(signfile);
  if (!sf) {
    std::cerr << "stpm-sign: Can't open file '" << signfile << "'\n";
    return usage(1);
  }
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
