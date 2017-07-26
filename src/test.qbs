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
import qbs.File

Project {
    name: "cjetUnitTests"
    minimumQbsVersion: "1.6.0"

    qbsSearchPaths: "../qbs/"
    references: "../qbs/unittestSettings.qbs"

    property bool buildHttpParserTest: true

    CppApplication {
        name: "info_test"
        type: ["application", "unittest"]
        consoleApplication: true

        Depends { name: "unittestSettings" }

        files: [
            "linux/timer_linux.c",
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
            "linux/timer_linux.c",
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
            "linux/timer_linux.c",
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
        name: "websocket_peer_test"
        type: ["application", "unittest"]
        consoleApplication: true

        Depends { name: "unittestSettings" }

        files: [
            "base64.c",
            "compression.c",
            "http-parser/http_parser.c",
            "http_connection.c",
            "http_server.c",
            "linux/jet_endian.c",
            "linux/timer_linux.c",
            "linux/random.c",
            "sha1/sha1.c",
            "tests/auth_stub.cpp",
            "tests/websocket_peer_test.cpp",
            "websocket.c",
            "websocket_peer.c",
        ]
    }

    CppApplication {
        name: "config_test"
        type: ["application", "unittest"]
        consoleApplication: true

        Depends { name: "unittestSettings" }

        files: [
            "linux/timer_linux.c",
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
            "linux/timer_linux.c",
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
            "linux/timer_linux.c",
            "tests/auth_stub.cpp",
            "tests/log.cpp",
            "tests/parse_test.cpp",
        ]
    }

    CppApplication {
        name: "state_test"
        type: ["application", "unittest"]
        consoleApplication: true

        Depends { name: "unittestSettings" }

        files: [
            "linux/timer_linux.c",
            "tests/auth_stub.cpp",
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
            "linux/timer_linux.c",
            "tests/log.cpp",
            "tests/auth_stub.cpp",
            "tests/method_test.cpp",
        ]
    }

    CppApplication {
        name: "combined_test"
        type: ["application", "unittest"]
        consoleApplication: true

        Depends { name: "unittestSettings" }

        files: [
            "linux/timer_linux.c",
            "tests/log.cpp",
            "tests/auth_stub.cpp",
            "tests/combined_test.cpp",
        ]
    }

    CppApplication {
        name: "fetch_test"
        type: ["application", "unittest"]
        consoleApplication: true

        Depends { name: "unittestSettings" }

        files: [
            "linux/timer_linux.c",
            "tests/log.cpp",
            "tests/auth_stub.cpp",
            "tests/fetch_test.cpp",
        ]
    }

    CppApplication {
        name: "base64_test"
        type: ["application", "unittest"]
        consoleApplication: true

        Depends { name: "unittestSettings" }

        files: [
            "base64.c",
            "tests/base64_test.cpp",
        ]
    }

    CppApplication {
        name: "alloc_test"
        type: ["application", "unittest"]
        consoleApplication: true

        Depends { name: "unittestSettings" }

        files: [
            "tests/alloc_test.cpp",
        ]
    }

    CppApplication {
        name: "access_test"
        type: ["application", "unittest"]
        consoleApplication: true

        Depends { name: "unittestSettings" }

        files: [
            "linux/timer_linux.c",
            "tests/access_test.cpp",
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
            "http-parser/http_parser.c",
            "http_connection.c",
            "http_server.c",
            "tests/http_connection_test.cpp",
        ]
    }

    CppApplication {
        name: "websocket_test"
        type: ["application", "unittest"]
        consoleApplication: true

        Depends {
          name: "unittestSettings"
        }

        files: [
            "base64.c",
            "buffered_socket.c",
            "compression.c",
            "http-parser/http_parser.c",
            "http_connection.c",
            "http_server.c",
            "linux/jet_endian.c",
            "linux/random.c",
            "sha1/sha1.c",
            "tests/websocket_test.cpp",
            "tests/log.cpp",
            "websocket.c",
        ]
    }

    CppApplication {
        name: "websocket_frame_test"
        type: ["application", "unittest"]
        consoleApplication: true

        Depends {
          name: "unittestSettings"
        }

        files: [
            "base64.c",
            "compression.c",
            "http-parser/http_parser.c",
            "http_connection.c",
            "http_server.c",
            "linux/jet_endian.c",
            "linux/random.c",
            "sha1/sha1.c",
            "tests/websocket_frame_test.cpp",
            "tests/log.cpp",
            "websocket.c",
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

    CppApplication {
        name: "auth_file_test"
        type: ["application", "unittest","passwd_test_files"]
        consoleApplication: true

        Depends { name: "unittestSettings" }

        files: [
            "posix/auth_file.c",
            "tests/auth_file_test.cpp",
        ]

        Group {
          name: "authenticate json files"
          files: ["tests/input_data/*.json"]
          fileTags: ["auth_test_source_files"]
        }

        cpp.dynamicLibraries: ["boost_filesystem", "gcov","crypt"]

        Rule {
          id: test_file_copy
          inputs: ["auth_test_source_files"]
          Artifact {
            filePath: "input_data/" + input.fileName
            fileTags: ["passwd_test_files"]
          }
          prepare: {
            var cmd = new JavaScriptCommand();
            cmd.description = "Copying '" + input.fileName + "'";
            cmd.highlight = "codegen";
            cmd.sourceCode = function() {
              var success = File.copy(input.filePath, output.filePath);
            }
            return [cmd];
          }
        }
    }

    CppApplication {
        name: "utf8_checker_test"
        type: ["application", "unittest"]
        consoleApplication: true

        Depends {name: "unittestSettings"}

        files: [
            "utf8_checker.c",
            "tests/utf8_checker_test.cpp",
        ]
    }

    CppApplication {
        name: "compression_test"
        type: ["application", "unittest"]
        consoleApplication: true

        Depends {name: "unittestSettings"}

        files: [
            "base64.c",
            "compression.c",
            "http-parser/http_parser.c",
            "http_connection.c",
            "http_server.c",
            "linux/jet_endian.c",
            "linux/random.c",
            "sha1/sha1.c",
            "tests/compression_test.cpp",
            "websocket.c",
        ]
    }
}
