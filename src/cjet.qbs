import qbs 1.0

Project {
  name: "cjet"
  minimumQbsVersion: "1.4.0"

  qbsSearchPaths: "../qbs/"

  CppApplication {
    name: "cjet"
    //profiles: targetProcessor

    Depends { name: "generateConfig" }
    Depends { name: "generateVersion" }

    cpp.warningLevel: "all"
    cpp.includePaths: ["linux/epoll/", ".", buildDirectory]

    Group {
      name: "platform independent"
      files: [
        "*.c",
      ]
    }

    Group {
      name: "linux specific"
      files: [
        "linux/*.c",
        "linux/epoll/*.c",
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

/*
    Group {
      name: "non ansi conformant"
      files: [
        "pocket-websocket/log.c", // required for vsnprintf, which is not ANSI
        "pocket-websocket/os_net.c" // required for vsnprintf, which is not ANSI
      ]
    }
*/
/*
    Properties {
      condition: qbs.buildVariant === "debug"
      cpp.defines: commonDefines.concat(["NIOS_A","OS_LIBMODE_DP","EMBOS"])
      cpp.cFlags: ["-O0"]
    }
    Properties {
      condition: qbs.buildVariant === "release"
      cpp.defines: {return commonDefines.concat(["NIOS_A"]).concat(["OS_LIBMODE_R","EMBOS"])}
    }
*/
  }
}
