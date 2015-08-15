/*
 *The MIT License (MIT)
 *
 * Copyright (c) <2014> <Stephan Gatzka>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import qbs 1.0

Project {
  name: "cjet_unit_tests"
  minimumQbsVersion: "1.4.0"

  qbsSearchPaths: "../../qbs/"
  references: "../../qbs/unitTestSettings.qbs"

  AutotestRunner { }

  CppApplication {
    name: "info_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "info_test.cpp",
      "log.cpp"
    ] 
  }

  CppApplication {
    name: "response_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "response_test.cpp",
    ] 
  }

  CppApplication {
    name: "router_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "log.cpp",
      "router_test.cpp",
    ] 
  }

  CppApplication {
    name: "string_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "string_test.cpp",
    ] 
  }

  CppApplication {
    name: "config_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "log.cpp",
      "config_test.cpp",
    ] 
  }

  CppApplication {
    name: "peer_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "peer_test.cpp",
      "log.cpp",
    ] 
  }

  CppApplication {
    name: "parse_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "parse_test.cpp",
    ] 
  }

  CppApplication {
    name: "state_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "log.cpp",
      "state_test.cpp",
    ] 
  }

  CppApplication {
    name: "method_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "log.cpp",
      "method_test.cpp",
    ] 
  }

  CppApplication {
    name: "combined_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "log.cpp",
      "combined_test.cpp",
    ] 
  }

  CppApplication {
    name: "fetch_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "log.cpp",
      "fetch_test.cpp",
    ] 
  } 
}
