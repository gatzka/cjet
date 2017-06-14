import qbs
Project {
    minimumQbsVersion: "1.6.0"

    CppApplication {
        consoleApplication: true
        cpp.includePaths: ["../"]

        files: [
            "../utf8_checker.c",
            "main.c",
        ]
        cpp.cLanguageVersion: "c99"

        Group {     // Properties for the produced executable
            fileTagsFilter: product.type
            qbs.install: true
        }
    }
}
