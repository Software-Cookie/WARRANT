rootProject.name = "warrant"

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

val modules = mapOf(
    "warrant-core" to "packages/warrant-core",
    "policy-dsl" to "packages/policy-dsl",
    "sdk-java" to "packages/sdk-java",
    "pep-gateway" to "apps/pep-gateway",
    "control-plane" to "apps/control-plane",
)

modules.forEach { (name, dir) ->
    include(name)
    project(":$name").projectDir = file(dir)
}
