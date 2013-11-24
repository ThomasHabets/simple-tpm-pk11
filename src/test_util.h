#include<iostream>
#include<string>

struct CaptureStreams {
  CaptureStreams()
    :stopped_(false),
     outold_(std::cout.rdbuf(outbuf_.rdbuf())),
     errold_(std::cerr.rdbuf(errbuf_.rdbuf())),
     logold_(std::clog.rdbuf(logbuf_.rdbuf()))
  {
  }

  void stop()
  {
    if (!stopped_) {
      std::cout.rdbuf(outold_);
      std::cerr.rdbuf(errold_);
      std::clog.rdbuf(logold_);
      stopped_ = true;
    }
  }
  std::string stdout() const { return outbuf_.str(); }
  std::string stderr() const { return errbuf_.str(); }
  std::string stdlog() const { return logbuf_.str(); }

  ~CaptureStreams()
  {
    stop();
  }

private:
  bool stopped_;
  std::stringstream outbuf_, errbuf_, logbuf_;
  std::streambuf *outold_, *errold_, *logold_;
};
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
