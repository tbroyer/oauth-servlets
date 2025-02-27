plugins {
    id("local.java-conventions")
    id("local.maven-publish-conventions")
    `java-library`
    `java-test-fixtures`
}

dependencies {
    api(platform(projects.oauthBom))

    api(libs.jspecify)
    api(libs.errorprone.annotations)
    api(libs.nimbus.oauthSdk)
    api(libs.caffeine)

    testFixturesApi(libs.junitJupiter.api)
    testFixturesApi(libs.nullaway.annotations)
}

// Don't publish test fixtures
// https://docs.gradle.org/current/userguide/java_testing.html#ex-disable-publishing-of-test-fixtures-variants
val javaComponent = components["java"] as AdhocComponentWithVariants
javaComponent.withVariantsFromConfiguration(configurations.testFixturesApiElements.get()) { skip() }
javaComponent.withVariantsFromConfiguration(configurations.testFixturesRuntimeElements.get()) { skip() }

testing {
    suites {
        withType<JvmTestSuite>().configureEach {
            useJUnitJupiter(libs.versions.junitJupiter)
        }
        named<JvmTestSuite>("test") {
            dependencies {
                implementation(libs.truth)
            }
        }
        register<JvmTestSuite>("functionalTest") {
            dependencies {
                implementation(project())
                implementation(testFixtures(project()))
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
        title = "OAuth Servlets Common API"
    }
}

publishing {
    publications {
        withType<MavenPublication>().configureEach {
            pom {
                name = "OAuth Servlets Common"
                description = "Common classes implementing OAuth, through the Nimbus SDK"
            }
        }
    }
}
