load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "webhook",
    srcs = ["webhook.go"],
    visibility = ["//website/cmd/server:__pkg__"],
    nogo = False,
    deps = [
        "@com_github_google_go_github_v28//github:go_default_library",
	"@com_google_cloud_go//secretmanager/apiv1:go_default_library",
	"@org_golang_google_genproto//googleapis/cloud/secretmanager/v1:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
    ],
)
