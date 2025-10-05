plugins {
    // Workaround for https://github.com/vanniktech/gradle-maven-publish-plugin/issues/786
    alias(libs.plugins.vanniktechMavenPublish) apply false
}
