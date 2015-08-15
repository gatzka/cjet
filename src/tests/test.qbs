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

    Group {
      name: "files to test"
      prefix: "../"
      files: [
        "info.c",
        "response.c",
      ]
    }
  }

  CppApplication {
    name: "response_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "response_test.cpp",
    ] 

    Group {
      name: "files to test"
      prefix: "../"
      files: [
        "linux/jet_string.c",
        "response.c",
      ]
    }
  }

  CppApplication {
    name: "router_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "log.cpp",
      "router_test.cpp",
    ] 

    Group {
      name: "files to test"
      prefix: "../"
      files: [
        "linux/jet_string.c",
        "peer.c",
        "response.c",
        "router.c",
      ]
    }
  }

  CppApplication {
    name: "string_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "string_test.cpp",
    ] 

    Group {
      name: "files to test"
      prefix: "../"
      files: [
        "linux/jet_string.c",
      ]
    }
  }

  CppApplication {
    name: "config_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "log.cpp",
      "config_test.cpp",
    ] 

    Group {
      name: "files to test"
      prefix: "../"
      files: [
        "linux/jet_string.c",
        "config.c",
        "peer.c",
        "response.c",
      ]
    }
  }

  CppApplication {
    name: "peer_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "peer_test.cpp",
      "log.cpp",
    ] 

    Group {
      name: "files to test"
      prefix: "../"
      files: [
        "linux/jet_string.c",
        "peer.c",
      ]
    }
  }

  CppApplication {
    name: "parse_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "parse_test.cpp",
    ] 

    Group {
      name: "files to test"
      prefix: "../"
      files: [
        "config.c",
        "info.c",
        "linux/jet_string.c",
        "parse.c",
        "response.c",
      ]
    }
  }

  CppApplication {
    name: "state_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "log.cpp",
      "state_test.cpp",
    ] 

    Group {
      name: "files to test"
      prefix: "../"
      files: [
        "linux/jet_string.c",
        "response.c",
        "router.c",
        "state.c",
        "peer.c",
        "uuid.c",
      ]
    }
  }

  CppApplication {
    name: "method_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "log.cpp",
      "method_test.cpp",
    ] 

    Group {
      name: "files to test"
      prefix: "../"
      files: [
        "linux/jet_string.c",
        "response.c",
        "router.c",
        "method.c",
        "peer.c",
        "uuid.c",
      ]
    }
  }

  CppApplication {
    name: "combined_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "log.cpp",
      "combined_test.cpp",
    ] 

    Group {
      name: "files to test"
      prefix: "../"
      files: [
        "fetch.c",
        "linux/jet_string.c",
        "method.c",
        "response.c",
        "router.c",
        "state.c",
        "peer.c",
        "uuid.c",
      ]
    }
  }

  CppApplication {
    name: "fetch_test"
    type: ["application", "autotest"]

    Depends { name: "unitTestSettings" }

    files: [
      "log.cpp",
      "fetch_test.cpp",
    ] 

    Group {
      name: "files to test"
      prefix: "../"
      files: [
        "fetch.c",
        "linux/jet_string.c",
        "response.c",
        "router.c",
        "state.c",
        "peer.c",
        "uuid.c",
      ]
    }
  }
}
