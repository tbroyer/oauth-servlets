plugins {
    id("local.java-conventions")
    id("local.maven-publish-conventions")
    `java-library`
}

dependencies {
    api(platform(projects.oauthBom))

    api(projects.oauthCommon)
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
                implementation(testFixtures(projects.oauthCommon))
                implementation(platform(libs.jetty.bom))
                implementation(platform(libs.jetty.ee10.bom))
                implementation(libs.jetty.servlet)
                implementation(libs.truth)
            }
            targets.configureEach {
                testTask {
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

mavenPublishing {
    pom {
        name = "OAuth Servlets"
        description = "Servlet filters implementing OAuth, through the Nimbus SDK"
    }
}
