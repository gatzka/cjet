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
    cpp.positionIndependentCode: false
    cpp.includePaths: ["linux/epoll/", ".", buildDirectory]

    Group {
      name: "platform independent"
      files: [
        "*.c",
      ]
    }

    Group {
      name: "linux specific"
      prefix: "linux/"
      files: [
        "*.c",
        "epoll/*.c",
      ]
    }

    Group {
      name: "cJSON"
      files: [
        "json/*.c",
      ]
    }

    Group {
      name: "config file"
      files: [
        "linux/epoll/config/config.h.in"
      ]
      fileTags: ["config_tag"]
    }

    Group {
      name: "version file"
      files: [
        "version.h.in"
      ]
      fileTags: ["version_tag"]
    }

    Properties {
      condition: qbs.targetOS.contains("linux")
      cpp.defines: {return ["gcc"]}
    }
  }
}
