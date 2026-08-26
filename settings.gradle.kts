rootProject.name = "bloodhound"

include("bloodhound-common")
include("central-server")
include("worker")
include("webui-backend")

project(":webui-backend").projectDir = file("webui/backend")
