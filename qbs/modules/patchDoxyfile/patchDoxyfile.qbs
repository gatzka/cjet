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
    id: doxy_src_patcher
    inputs:  ["doxy_input"]

    Artifact {
      alwaysUpdated: false
      filePath: "generated/Doxyfile.src.in"
      fileTags: ["doxy_src_patched"]
    }

    prepare: {
  	  var cmd = new JavaScriptCommand();
  	  cmd.description = "Processing '" + input.fileName + "'";
  	  cmd.highlight = "codegen";
  	  cmd.sourceCode = function() {
  	    var file = new TextFile(input.filePath);
  	    var content = file.readAll();
  	    file.close()
  	    content = content.replace(/\${CJET_BUILD_DIR}/g, product.buildDirectory);
  	    file = new TextFile(output.filePath,  TextFile.WriteOnly);
  	    file.truncate();
  	    file.write(content);
  	    file.close();
  	  }
  	  return  cmd;
	}
  }
}

