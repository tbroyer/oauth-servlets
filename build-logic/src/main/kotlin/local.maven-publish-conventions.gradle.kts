import org.gradle.api.publish.maven.MavenPublication
import org.gradle.kotlin.dsl.*

plugins {
    id("com.vanniktech.maven.publish")
    signing
}

group = "net.ltgt.oauth"

mavenPublishing {
    publishToMavenCentral(automaticRelease = true)
    signAllPublications()
    pom {
        url = "https://github.com/tbroyer/oauth-servlets"
        licenses {
            license {
                name = "The Apache License, Version 2.0"
                url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
            }
        }
        developers {
            developer {
                name = "Thomas Broyer"
                email = "t.broyer@ltgt.net"
            }
        }
        scm {
            connection = "https://github.com/tbroyer/oauth-servlets.git"
            developerConnection = "scm:git:ssh://github.com:tbroyer/oauth-servlets.git"
            url = "https://github.com/tbroyer/oauth-servlets"
        }
    }
}

pluginManager.withPlugin("java") {
    publishing {
        publications {
            withType<MavenPublication> {
                versionMapping {
                    usage("java-api") {
                        fromResolutionOf("runtimeClasspath")
                    }
                    usage("java-runtime") {
                        fromResolutionResult()
                    }
                }
            }
        }
    }
}

signing {
    useGpgCmd()
}
