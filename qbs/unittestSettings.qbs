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
  name: "unittestSettings"

  Depends { name: 'cpp' }
  Depends { name: "generateVersion" } 
  Depends { name: "generateCjetConfig" }
  Depends { name: "generateOsConfig" }

  cpp.includePaths: ["../src/", "../src/zlib", product.buildDirectory]
  cpp.defines: ["BOOST_SYSTEM_NO_DEPRECATED", "_GNU_SOURCE", "TESTING"]
  cpp.treatWarningsAsErrors: true
  cpp.cFlags: [
    "-fprofile-arcs",
    "-ftest-coverage"
  ]
  cpp.driverFlags: ["--coverage"]

  Export {
    Depends { name: 'cpp' }

    cpp.warningLevel: "all"
    cpp.treatWarningsAsErrors: false
    cpp.includePaths: ["../src/", "../src/zlib", product.buildDirectory]
    cpp.defines: ["_GNU_SOURCE", "BOOST_SYSTEM_NO_DEPRECATED", "TESTING"]
    cpp.dynamicLibraries: ["boost_unit_test_framework", "gcov","crypt"]
    cpp.cLanguageVersion: "c99"
    cpp.driverFlags: ["--coverage"]
  	cpp.cFlags: [
  	  "-fprofile-arcs",
  	  "-ftest-coverage"
  	]
  }

  Group {
    name: "version header"
    prefix: "../src/"
    files: [
      "version.h.in"
    ]
    fileTags: ["version_file_patched"]
  }

  Group {
    name: "version file"
    prefix: "../src/"
    files: [
      "version"
    ]
    fileTags: ["version_file"]
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
    name: "zlib"
    prefix: "../src/"
    cpp.cFlags: ["-DNO_GZIP"]
    files: [
      "zlib/*.c",
    ]
    excludeFiles: [
      "zlib/g*.c",
      "zlib/g*.h",
      "zlib/infback.c",
      "zlib/inffixed.h",
      "zlib/compress.*",
      "zlib/uncompr.c",
      "zlib/crc32.*",
    ]
  }

  Group {
    name: "cjet files"
    prefix: "../src/"
    cpp.cLanguageVersion: "c99"
    files: [
        "alloc.c",
        "authenticate.c",
        "compression.c",
        "config.c",
        "element.c",
        "fetch.c",
        "groups.c",
        "info.c",
        "jet_string.c",
        "linux/jet_string.c",
        "parse.c",
        "peer.c",
        "posix/jet_string.c",
        "response.c",
        "router.c",
        "table.c",
        "tests/log.cpp",
        "timer.c",
        "utf8_checker.c",
    ]
  }
}

