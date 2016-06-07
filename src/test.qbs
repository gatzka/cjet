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

  qbsSearchPaths: "../qbs/"
  references: "../qbs/unittestSettings.qbs"

  property bool buildHttpParserTest: true

  CppApplication {
    name: "info_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends {
      name: "unittestSettings"
    }

    files: [
      "tests/info_test.cpp",
      "tests/log.cpp",
    ] 
  }

  CppApplication {
    name: "response_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends { name: "unittestSettings" }

    files: [
      "tests/response_test.cpp",
      "tests/log.cpp",
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
      "tests/log.cpp",
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
    name: "base64_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends {
      name: "unittestSettings"
    }

    files: [
      "base64.c",
      "tests/base64_test.cpp",
    ] 
  }

  CppApplication {
    name: "buffered_socket_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends {
      name: "unittestSettings"
    }

    files: [
        "buffered_socket.c",
        "tests/buffered_socket_test.cpp",
        "tests/log.cpp"
    ]
  }
  
  CppApplication {
    name: "http_connection_test"
    type: ["application", "unittest"]
    consoleApplication: true

    Depends {
      name: "unittestSettings"
    }

    files: [
          "buffered_socket.c",
          "http-parser/http_parser.c",
          "http_connection.c",
          "http_server.c",
          "tests/http_connection_test.cpp",
          "tests/log.cpp",
      ]
  }

  CppApplication {
    name: "http_parse_test"
    type: ["application", "unittest"]
    consoleApplication: true

    condition: buildHttpParserTest

    Depends {
      name: "unittestSettings"
    }

    files: [
      "http-parser/http_parser.c",
      "http-parser/test.c",
    ] 
  }
}
