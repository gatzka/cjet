import qbs 1.0
import qbs.TextFile

Module {
  Rule {
    id: config_generator
    inputs:  ["cjet_config_tag"]

    Artifact {
      filePath: "config/cjet_config.h"
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
        content = content.replace(/\${CONFIG_SERVER_PORT}/g, "11122");
        content = content.replace(/\${CONFIG_LISTEN_BACKLOG}/g, "40");
        content = content.replace(/\${CONFIG_MAX_MESSAGE_SIZE}/g, "512");
        content = content.replace(/\${CONFIG_MAX_WRITE_BUFFER_SIZE}/g, "5120");
        content = content.replace(/\${CONFIG_STATE_TABLE_ORDER}/g, "13");
        content = content.replace(/\${CONFIG_METHOD_TABLE_ORDER}/g, "10");
        content = content.replace(/\${CONFIG_ROUTING_TABLE_ORDER}/g, "6");
        content = content.replace(/\${CONFIG_INITIAL_FETCH_TABLE_SIZE}/g, "4");
        content = content.replace(/\${CONFIG_ROUTED_MESSAGES_TIMEOUT}/g, "5.0");
        file = new TextFile(output.filePath,  TextFile.WriteOnly);
        file.truncate();
        file.write(content);
        file.close();
      }
      return  cmd;
    }
  }
}
