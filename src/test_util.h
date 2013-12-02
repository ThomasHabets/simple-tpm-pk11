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
#ifndef __INCLUDE__SIMPLE_TPM_PK11_TEST_UTIL_H__
#define __INCLUDE__SIMPLE_TPM_PK11_TEST_UTIL_H__
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
#endif
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
