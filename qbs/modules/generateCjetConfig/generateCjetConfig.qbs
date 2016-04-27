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

Module {
  property string jetPort
  property string jetwsPort
  property string maxListenBacklog
  property string maxMessageSize
  property string maxWriteBufferSize
  property string stateTableOrder
  property string methodTableOrder
  property string routingTableOrder
  property string initialFetchTableSize
  property string routedMessagesTimeout

  Rule {
    id: config_generator
    inputs:  ["cjet_config_tag"]

    Artifact {
      filePath: "generated/cjet_config.h"
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
        content = content.replace(/\${CONFIG_JET_PORT}/g, product.moduleProperty("generateCjetConfig", "jetPort") || "11122");
        content = content.replace(/\${CONFIG_JETWS_PORT}/g, product.moduleProperty("generateCjetConfig", "jetwsPort") || "11123");
        content = content.replace(/\${CONFIG_LISTEN_BACKLOG}/g, product.moduleProperty("generateCjetConfig", "maxListenBacklog") || "40");
        content = content.replace(/\${CONFIG_MAX_MESSAGE_SIZE}/g, product.moduleProperty("generateCjetConfig", "maxMessageSize") || "512");
        content = content.replace(/\${CONFIG_MAX_WRITE_BUFFER_SIZE}/g, product.moduleProperty("generateCjetConfig", "maxWriteBufferSize") || "5120");
        content = content.replace(/\${CONFIG_STATE_TABLE_ORDER}/g, product.moduleProperty("generateCjetConfig", "stateTableOrder") || "13");
        content = content.replace(/\${CONFIG_ROUTING_TABLE_ORDER}/g, product.moduleProperty("generateCjetConfig", "routingTableOrder") || "6");
        content = content.replace(/\${CONFIG_INITIAL_FETCH_TABLE_SIZE}/g, product.moduleProperty("generateCjetConfig", "initialFetchTableSize") || "4");
        content = content.replace(/\${CONFIG_ROUTED_MESSAGES_TIMEOUT}/g, product.moduleProperty("generateCjetConfig", "routedMessagesTimeout") || "5.0");
        content = content.replace(/\${CONFIG_MAX_NUMBERS_OF_MATCHERS_IN_FETCH}/g, product.moduleProperty("generateCjetConfig", "maxMatchersInFetch") || "12");
        file = new TextFile(output.filePath,  TextFile.WriteOnly);
        file.truncate();
        file.write(content);
        file.close();
      }
      return  cmd;
    }
  }
}
