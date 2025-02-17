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

include(":oauth-servlets")
project(":oauth-servlets").projectDir = file("lib")

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")
