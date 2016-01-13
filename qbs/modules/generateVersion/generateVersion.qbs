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
import qbs.TextFile
import qbs.Process

Module {
  Rule {
    id: version_generator
    inputs:  ["version_tag"]

    Artifact {
      alwaysUpdated: false
      filePath: "generated/version.h"
      fileTags: ["hpp"]
    }

    prepare: {
      var cmd = new JavaScriptCommand();
      cmd.description = "Processing '" + input.fileName + "'";
      cmd.highlight = "codegen";
      cmd.sourceCode = function() {
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
        var pat = content.match(/\s*#define\s+CJET_PATCH\s+"(\d+)"/);

        var last;
        if (pat[1] %2 === 0) {
          last = "0";
        } else {
          var gitCount = new Process();
          gitCount.setWorkingDirectory(product.sourceDirectory);
          gitCount.exec("git", ["rev-list","HEAD","--count"], true)
          last = gitCount.readLine();
          gitCount.close();
        }

        content = content.replace(/\${CJET_LAST}/g, last+"-"+dirty);
        content = content.replace(/\${PROJECT_NAME}/g, product.name);
        file = new TextFile(output.filePath,  TextFile.WriteOnly);
        file.truncate();
        file.write(content);
        file.close();
      }
      return  cmd;
    }
  }
}
