rootProject.name = "oauth-servlets-parent"

pluginManagement {
    includeBuild("build-logic")
}

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        mavenCentral()
    }
}

fun include(
    projectPath: String,
    projectDir: String,
) {
    include(projectPath)
    project(projectPath).projectDir = file(projectDir)
}
include(":oauth-common", "common")
include(":oauth-servlets", "lib")

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")
