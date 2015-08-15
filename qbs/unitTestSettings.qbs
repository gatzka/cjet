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

StaticLibrary {
  name: "unitTestSettings"

  Depends { name: 'cpp' }
  Depends { name: "generateVersion" } 
  Depends { name: "generateCjetConfig" }
  Depends { name: "generateOsConfig" }

  cpp.includePaths: ["../src/", buildDirectory]
  cpp.defines: ["BOOST_SYSTEM_NO_DEPRECATED", "_GNU_SOURCE", "TESTING"]
  cpp.treatWarningsAsErrors: true

  Export {
    Depends { name: 'cpp' }

    cpp.warningLevel: "all"
    cpp.treatWarningsAsErrors: true
    cpp.includePaths: ["../src/", buildDirectory]
    cpp.defines: ["BOOST_SYSTEM_NO_DEPRECATED", "TESTING"]
    cpp.dynamicLibraries: ["boost_unit_test_framework"]
    cpp.cLanguageVersion: "c99"
  }

  Group {
    name: "version file"
    prefix: "../src/"
    files: [
      "version.h.in"
    ]
    fileTags: ["version_tag"]
  }

  Group {
    name: "cjet config file"
    prefix: "../src/"
    files: [
      "cjet_config.h.in"
    ]
    fileTags: ["cjet_config_tag"]
  }

  Group {
    condition: qbs.targetOS.contains("linux")
    name: "linux config file"
    prefix: "../src/"
    files: [
      "linux/config/os_config.h.in"
    ]
    fileTags: ["os_config_tag"]
  }

  Group {
    name: "json"
    prefix: "../src/"
    cpp.cLanguageVersion: "c99"
    files: [
      "json/*.c",
    ]
  }

  Group {
    name: "cjet files"
    prefix: "../src/"
    cpp.cLanguageVersion: "c99"
    files: [
        "config.c",
        "fetch.c",
        "info.c",
        "linux/jet_string.c",
        "method.c",
        "parse.c",
        "peer.c",
        "response.c",
        "router.c",
        "state.c",
        "uuid.c",
    ]
  }
}

