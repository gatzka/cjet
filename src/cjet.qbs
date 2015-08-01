import qbs 1.0

Project {
  name: "cjet"
  minimumQbsVersion: "1.4.0"

  qbsSearchPaths: "../qbs/"

  CppApplication {
    name: "cjet"

    Depends { name: "generateConfig" }
    Depends { name: "generateVersion" }

    cpp.warningLevel: "all"
    cpp.treatWarningsAsErrors: true
    cpp.positionIndependentCode: false
    cpp.includePaths: ["linux/epoll/", ".", buildDirectory]

    Group {
      name: "platform independent"
      files: [
        "*.c",
      ]
      cpp.cLanguageVersion: "c99"
    }

    Group {
      name: "cJSON"
      files: [
        "json/*.c",
      ]
      cpp.cLanguageVersion: "c99"
    }

    Group {
      name: "version file"
      files: [
        "version.h.in"
      ]
      fileTags: ["version_tag"]
    }

    Group {
      condition: qbs.targetOS.contains("linux")
      name: "config file"
      files: [
        "linux/epoll/config/config.h.in"
      ]
      fileTags: ["config_tag"]
    }

    Group {
      condition: qbs.targetOS.contains("linux")
      name: "linux specific"
      prefix: "linux/"
      files: [
        "*.c",
        "epoll/*.c",
      ]
      cpp.defines: "_GNU_SOURCE"
      cpp.cFlags: "-std=gnu99"
    }

    Properties {
      condition: qbs.toolchain.contains("gcc")
     // cpp.defines: outer.concat("gcc")
    }
  }
}
