#include<cstdlib>
#include<fstream>
#include<iostream>
#include<unistd.h>

#include"common.h"
#include"internal.h"

BEGIN_NAMESPACE();
int
usage(int rc)
{
  std::cout << "Usage: keygen [ -hv ] -o <output file>\n";
  return rc;
}
END_NAMESPACE();

int
wrapped_main(int argc, char **argv)
{
  int c;
  std::string output;
  while (EOF != (c = getopt(argc, argv, "ho:v"))) {
    switch (c) {
    case 'h':
      return usage(0);
    case 'o':
      output = optarg;
      break;
    default:
      return usage(1);
    }
  }
  if (output.empty()) {
    return usage(1);
  }
  auto key = stpm::generate_key();
  std::ofstream fo(output);
  fo << "# Some sort of key\n"
     << "exp " << stpm::to_hex(key.exponent) << std::endl
     << "mod " << stpm::to_hex(key.modulus) << std::endl
     << "blob " << stpm::to_hex(key.blob) << std::endl;
  return 0;
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
