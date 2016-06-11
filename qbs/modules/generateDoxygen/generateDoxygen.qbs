/*
 *The MIT License (MIT)
 *
 * Copyright (c) <2016> <Stephan Gatzka>
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
    inputs: ["doxy_src_patched", "source"];
    multiplex: "true";
    prepare: {
      var cmd = new JavaScriptCommand();
      cmd.description = "generating documentation from doxygen config";
      cmd.highlight = "doxygen";
      cmd.sourceCode = function() {
        for (var idx = 0; idx < inputs["doxy_src_patched"].length; idx++) {
          var file = inputs["doxy_src_patched"][idx].filePath;
          var proc = new Process();
          proc.setWorkingDirectory(product.sourceDirectory);
          print(file)
          print(product.sourceDirectory)
          proc.exec("doxygen", [file], true);
          proc.close();
        } 
      }
      return cmd;
    }

    Artifact {
        fileTags: ["docs"];
        filePath: "force.doc";
    }
  }
}

