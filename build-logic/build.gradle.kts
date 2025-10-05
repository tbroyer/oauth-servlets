plugins {
    `kotlin-dsl`
    alias(libs.plugins.spotless)
}

dependencies {
    implementation(plugin(libs.plugins.spotless))
    implementation(plugin(libs.plugins.errorprone))
    implementation(plugin(libs.plugins.nullaway))
    implementation(plugin(libs.plugins.jvmDependencyConflictResolution))
    implementation(plugin(libs.plugins.vanniktechMavenPublish))
}

spotless {
    kotlinGradle {
        target("*.gradle.kts", "src/**/*.gradle.kts")
        ktlint(libs.versions.ktlint.get())
    }
}

// Simplifies declaration of dependencies on gradle plugins
// https://github.com/gradle/gradle/issues/17963
// https://docs.gradle.org/current/userguide/plugins.html#sec:plugin_markers
fun plugin(plugin: Provider<PluginDependency>) = plugin.map { "${it.pluginId}:${it.pluginId}.gradle.plugin:${it.version}" }
