load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "server",
    srcs = ["main.go"],
    pure = True,
    nogo = False,
    visibility = ["//website:__pkg__"],
    deps = ["//website/pkg/webhook"],
)
