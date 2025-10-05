plugins {
    id("local.java-conventions")
    id("local.maven-publish-conventions")
    `java-library`
}

dependencies {
    api(platform(projects.oauthBom))

    api(projects.oauthCommon)
    api(libs.jakarta.annotationApi)
    api(libs.jakarta.rsApi)
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
                implementation(platform(libs.resteasy.bom))
                implementation(libs.resteasy.core)
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
        title = "OAuth RS API"
    }
}

mavenPublishing {
    pom {
        name = "OAuth RS"
        description = "Jakarta RS filters implementing OAuth, through the Nimbus SDK"
    }
}
