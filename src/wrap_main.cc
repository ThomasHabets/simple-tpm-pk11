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
