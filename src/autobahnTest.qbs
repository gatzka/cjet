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
import '../qbs/versions.js' as Versions

Project {

  property bool runAnalyzer: false

  name: "autobahnTest"
  minimumQbsVersion: "1.6.0"

  qbsSearchPaths: "../qbs/"

  SubProject {
    filePath: "../qbs/hardening.qbs"
    Properties {
      name: "hardening settings"
    }
  }

  SubProject {
    filePath: "../qbs/gccClang.qbs"
    Properties {
      name: "GCC/Clang switches"
    }
  }

  CppApplication {
    name: "autobahnTest"

    Depends { name: "gccClang" }
    Depends { name: "hardening" }
    Depends { name: "generateAutobahnConfig" }
    Depends { name: "generateOsConfig" }
    Depends { name: "generateVersion" }

    consoleApplication: true
    
    cpp.warningLevel: "all"
    cpp.treatWarningsAsErrors: true
    cpp.positionIndependentCode: false
    cpp.includePaths: [".", buildDirectory]
    cpp.visibility: "hidden"
    cpp.useRPaths: false
    cpp.dynamicLibraries: ["m", "crypt"]

    Group {
      name: "installation files"
      qbs.install: true
      qbs.installDir: "bin"
      fileTagsFilter: "application"
    }

    Group {
      name: "ANSI C conformant"
      files: [
        "*.c",
        "*.h",
        "./autobahnfiles/abWebsocket_peer.c",
        "./autobahnfiles/abWebsocket_peer.h",
        "./autobahnfiles/abLog.h"
      ]
      excludeFiles: [
        "websocket_peer.c",
        "websocket_peer.h",
      ]
      cpp.cLanguageVersion: "c99"
    }

    Group {
      name: "third party"
      cpp.cLanguageVersion: "c99"
      files: [
        "json/*.c",
        "json/*.h",
        "http-parser/http_parser.c",
        "http-parser/http_parser.h",
        "sha1/sha1.c",
        "sha1/sha1.h",
      ]
    }

    Group {
      name: "zlib"
      cpp.warningLevel: "none"
//      cpp.defines: ["MAX_WBITS=-15"]
      cpp.cFlags: "-DMAX_WBITS=-15"
      files: [
        "zlib/*.c",
        "zlib/*.h"
      ]
    }

    Group {
      name: "version header"
      files: [
        "version.h.in"
      ]
      fileTags: ["version_file_patched"]
    }

    Group {
      name: "version file"
      files: [
        "version"
      ]
      fileTags: ["version_file"]
    }

    Group {
      name: "cjet config file"
      files: [
        "cjet_config.h.in"
      ]
      fileTags: ["cjet_config_tag"]
    }

    Group {
      condition: qbs.targetOS.contains("linux")
      name: "linux config file"
      files: [
        "linux/config/os_config.h.in"
      ]
      fileTags: ["os_config_tag"]
    }

    Group {
      condition: qbs.targetOS.contains("unix")
      name: "posix specific"
      cpp.cLanguageVersion: "c99"
      prefix: "posix/"
      files: [
        "*.c",
        "*.h",
        "../autobahnfiles/abLog.c",
        "../autobahnfiles/abMain.c"
      ]
      excludeFiles: [
          "main.c",
          "log.c"
      ]
      cpp.defines: "_XOPEN_SOURCE=500"
    }

    Group {
      condition: qbs.targetOS.contains("linux")
      name: "linux specific"
      cpp.cLanguageVersion: "c99"
      prefix: "linux/"
      files: [
        "*.c",
        "*.h",
        "../autobahnfiles/abLinux_io.c"
      ]
      excludeFiles: [
          "linux_io.c"
      ]
      cpp.defines: "_GNU_SOURCE"
    }

    Properties {
      condition: cpp.compilerName.contains("clang") && project.runAnalyzer;
      cpp.compilerWrapper: ["scan-build", "--view"];
    }

    Properties {
      condition: Versions.versionIsAtLeast(qbs.version, "1.5.0") >= 0;
      cpp.enableReproducibleBuilds: true;
    }
  }
}
