load("//tools:defs.bzl", "go_add_tags", "go_embed_data", "go_library")

package(licenses = ["notice"])

go_embed_data(
    name = "vdso_bin",
    src = "//vdso:vdso.so",
    package = "vdsodata",
    var = "Binary",
)

[
    # Generate multiple tagged targets. Note that the content will always be
    # the same, but we will select only the appropriate source below. This gets
    # around starlark limitations on "out" being a configurable attribute.
    go_add_tags(
        name = "vdso_%s" % arch,
        src = ":vdso_bin",
        out = "vdso_%s.go" % arch,
        go_tags = [arch],
    )
    for arch in ("amd64", "arm64")
]

go_library(
    name = "vdsodata",
    srcs = [
        "vdsodata.go",
        ":vdso_amd64",
        ":vdso_arm64",
    ],
    marshal = False,
    stateify = False,
    visibility = ["//pkg/sentry:internal"],
)
