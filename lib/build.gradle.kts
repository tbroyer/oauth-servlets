plugins {
    id("local.java-conventions")
    id("local.maven-publish-conventions")
    `java-library`
}

dependencies {
    api(libs.jspecify)
    api(libs.errorprone.annotations)
    api(libs.nimbus.oauthSdk)
    api(libs.jakarta.servletApi)
    api(libs.caffeine)
}

testing {
    suites {
        withType<JvmTestSuite>().configureEach {
            useJUnitJupiter(libs.versions.junitJupiter)
        }
        register<JvmTestSuite>("functionalTest") {
            dependencies {
                implementation(project())
                implementation(libs.nullaway.annotations)
                implementation(platform(libs.jetty.bom))
                implementation(platform(libs.jetty.ee10.bom))
                implementation(libs.jetty.servlet)
                implementation(libs.truth) {
                    // See https://github.com/google/truth/issues/333
                    exclude(group = "junit", module = "junit")
                }
                runtimeOnly(libs.truth) // to add junit:junit back
            }
            targets.configureEach {
                testTask {
                    systemProperty("test.port", 8000)
                    systemProperty("test.issuer", "http://localhost:8080/realms/example")
                    systemProperty("test.app.clientId", "app")
                    systemProperty("test.app.clientSecret", "example")
                    systemProperty("test.api.clientId", "api")
                    systemProperty("test.api.clientSecret", "example")
                }
            }
        }
    }
}

tasks {
    javadoc {
        title = "OAuth Servlets API"
    }
}

publishing {
    publications {
        withType<MavenPublication>().configureEach {
            pom {
                name = "OAuth Servlets"
                description = "Servlets implementing OAuth, through the Nimbus SDK"
            }
        }
    }
}
