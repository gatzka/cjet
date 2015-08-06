import qbs 1.0
import qbs.TextFile

Module {
  Rule {
    id: config_generator
    inputs:  ["os_config_tag"]

    Artifact {
      filePath: "generated/os_config.h"
      fileTags: ["hpp"]
    }

    prepare: {
      var cmd = new JavaScriptCommand();
      cmd.description = "Processing '" + input.fileName + "'";
      cmd.highlight = "codegen";
      cmd.sourceCode = function() {

        var file = new TextFile(input.filePath);
        var content = file.readAll();
        file.close()
        content = content.replace(/\${CONFIG_MAX_EPOLL_EVENTS}/g, "10");
        file = new TextFile(output.filePath,  TextFile.WriteOnly);
        file.truncate();
        file.write(content);
        file.close();
      }
      return  cmd;
    }
  }
}
