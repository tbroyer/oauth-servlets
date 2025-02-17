plugins {
    id("local.common-conventions")
    alias(libs.plugins.nexusPublish)
}

nexusPublishing {
    packageGroup = "net.ltgt.oauth"
    useStaging = !version.toString().endsWith("-SNAPSHOT")
    repositories {
        sonatype()
    }
}
