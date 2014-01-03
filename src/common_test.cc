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
#include"gtest/gtest.h"

#include"common.h"

TEST(Common, ToHex)
{
  std::vector<std::pair<std::string, std::string>> tests = {
    {"",""},
    {"414243", "ABC"},
    {"616263", "abc"},
    {"303132", "012"},
    {"20217b7dff01", " !{}\xff\x01"},
    {"00414243006162630100", std::string("\0ABC\0abc\x1\0", 10)},
  };
  for (auto& test : tests) {
    EXPECT_EQ(test.first, stpm::to_hex(test.second));
    EXPECT_EQ(test.second, stpm::to_bin(stpm::to_hex(test.second)));
  }
}
