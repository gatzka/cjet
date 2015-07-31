import qbs 1.0
import qbs.TextFile
import qbs.Process

Module {
  Rule {
    id: version_generator
    inputs:  ["version_tag"]

    Artifact {
      alwaysUpdated: false
      filePath: "version.h"
      fileTags: ["hpp"]
    }

    prepare: {
      var cmd = new JavaScriptCommand();
      cmd.description = "Processing '" + input.fileName + "'";
      cmd.highlight = "codegen";
      cmd.sourceCode = function() {
        var major = "0";
        var minor = "1";
        var patch = "3";
        var gitDescribe = new Process();
        gitDescribe.setWorkingDirectory(product.sourceDirectory);
        var ret = gitDescribe.exec("git", ["describe","--exact-match","HEAD"], false);
        var last;
        if (ret === 0) {
          last = "0";
        } else {
          var gitCount = new Process();
          gitCount.setWorkingDirectory(product.sourceDirectory);
          gitCount.exec("git", ["rev-list","HEAD","--count"], true)
          last = gitCount.readLine();
          gitCount.close();
        }
        gitDescribe.close();
        
        var gitRevParse = new Process();
        gitRevParse.setWorkingDirectory(product.sourceDirectory);
        gitRevParse.exec("git", ["rev-parse","--verify","HEAD"], true);
        var hash = gitRevParse.readLine();
        gitRevParse.close();

        var gitDirty = new Process();
        gitDirty.setWorkingDirectory(product.sourceDirectory);
        ret = gitDirty.exec("git", ["diff-index","--quiet","HEAD"], false);
        var dirty;
        if (ret === 0) {
          dirty = "clean";
        } else {
          dirty = "dirty";
        }
        gitDirty.close();

        var file = new TextFile(input.filePath);
        var content = file.readAll();
        file.close()
        content = content.replace(/\${PROJECT_NAME}/g, product.name);
        content = content.replace(/\${\${PROJECTNAME}_VERSION}/g, major+"."+minor+"."+patch+"."+last+"-"+dirty);
        file = new TextFile(output.filePath,  TextFile.WriteOnly);
        file.truncate();
        file.write(content);
        file.close();
      }
      return  cmd;
    }
  }
}
