import qbs 1.0

Project {
  name: "cjet"
  minimumQbsVersion: "1.4.0"

  qbsSearchPaths: "../qbs/"

  CppApplication {
    name: "cjet"

    Depends { name: "generateCjetConfig" }
    Depends { name: "generateOsConfig" }
    Depends { name: "generateVersion" }

    cpp.warningLevel: "all"
    cpp.treatWarningsAsErrors: true
    cpp.positionIndependentCode: false
    cpp.includePaths: [".", buildDirectory]
    cpp.visibility: "hidden"
    cpp.useRPaths: false

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
      condition: qbs.targetOS.contains("linux")
      name: "linux specific"
      prefix: "linux/"
      files: [
        "*.c",
      ]
      cpp.defines: "_GNU_SOURCE"
      cpp.cFlags: "-std=gnu99"
      cpp.includePaths: outer.concat("linux")
    }

    Properties {
      condition: qbs.toolchain.contains("gcc")
     // cpp.defines: outer.concat("gcc")
    }
  }
}
