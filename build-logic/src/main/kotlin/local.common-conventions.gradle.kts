plugins {
    id("com.diffplug.spotless")
}

tasks.withType<AbstractCopyTask>().configureEach {
    filteringCharset = "UTF-8"
}

spotless {
    kotlinGradle {
        ktlint(project.versionCatalogs.named("libs").findVersion("ktlint").orElseThrow().requiredVersion)
    }
}

