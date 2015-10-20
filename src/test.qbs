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
import "../qbs/unittestRunner.qbs" as UnittestRunner

Project {
  name: "cjet_unit_tests"
  minimumQbsVersion: "1.4.0"

  qbsSearchPaths: "../qbs/"
  references: "../qbs/unittestSettings.qbs"

  UnittestRunner {
    lcovRemovePatterns: [
      "*/cjet/src/json/*",
    ]
    wrapper: [
      "valgrind",
      "--errors-for-leak-kinds=all",
      "--show-leak-kinds=all",
      "--leak-check=full",
      "--error-exitcode=1",
      "--suppressions=" + sourceDirectory + "/../valgrind/valgrind.supp"
    ]
  }

  CppApplication {
    name: "info_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends {
      name: "unittestSettings"
    }

    files: [
      "tests/info_test.cpp",
      "tests/log.cpp"
    ] 
  }

  CppApplication {
    name: "response_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends { name: "unittestSettings" }

    files: [
      "tests/response_test.cpp",
    ] 
  }

  CppApplication {
    name: "router_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends { name: "unittestSettings" }

    files: [
      "tests/log.cpp",
      "tests/router_test.cpp",
    ] 
  }

  CppApplication {
    name: "string_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends { name: "unittestSettings" }

    files: [
      "tests/string_test.cpp",
    ] 
  }

  CppApplication {
    name: "config_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends { name: "unittestSettings" }

    files: [
      "tests/log.cpp",
      "tests/config_test.cpp",
    ] 
  }

  CppApplication {
    name: "peer_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends { name: "unittestSettings" }

    files: [
      "tests/peer_test.cpp",
      "tests/log.cpp",
    ] 
  }

  CppApplication {
    name: "parse_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends { name: "unittestSettings" }

    files: [
      "tests/parse_test.cpp",
    ] 
  }

  CppApplication {
    name: "state_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends { name: "unittestSettings" }

    files: [
      "tests/log.cpp",
      "tests/state_test.cpp",
    ] 
  }

  CppApplication {
    name: "method_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends { name: "unittestSettings" }

    files: [
      "tests/log.cpp",
      "tests/method_test.cpp",
    ] 
  }

  CppApplication {
    name: "combined_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends { name: "unittestSettings" }

    files: [
      "tests/log.cpp",
      "tests/combined_test.cpp",
    ] 
  }

  CppApplication {
    name: "fetch_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends { name: "unittestSettings" }

    files: [
      "tests/log.cpp",
      "tests/fetch_test.cpp",
    ] 
  }

  CppApplication {
    name: "readbuffer_test"
    type: ["application", "unittest"]
    consoleApplication: true

    cpp.defines: ["_GNU_SOURCE"]

    Depends {
      name: "unittestSettings"
    }

    files: [
      "linux/linux_io.c",
      "linux/tests/readbuffer_test.cpp",
      "linux/tests/log.cpp"
    ] 
  }
}
