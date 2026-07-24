import net.ltgt.gradle.errorprone.errorprone
import net.ltgt.gradle.nullaway.nullaway

plugins {
    id("local.common-conventions")
    `java-base`
    id("net.ltgt.errorprone")
    id("net.ltgt.nullaway")
    id("org.gradlex.jvm-dependency-conflict-resolution")
}

jvmDependencyConflicts {
    patch {
        // See https://github.com/google/truth/issues/333
        module("com.google.truth:truth") {
            reduceToRuntimeOnlyDependency("junit:junit")
        }
        module("com.google.guava:guava-testlib") {
            reduceToRuntimeOnlyDependency("junit:junit")
        }
    }
}

dependencies {
    errorprone(project.versionCatalogs.named("libs").findBundle("errorprone").orElseThrow())
}

nullaway {
    onlyNullMarked = true
    jspecifyMode = true
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
}

// Configure toolchain only if needed
if (!JavaVersion.current().isCompatibleWith(java.sourceCompatibility)) {
    java {
        toolchain {
            languageVersion = JavaLanguageVersion.of(java.sourceCompatibility.majorVersion)
        }
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.release = java.sourceCompatibility.majorVersion.toInt()
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(arrayOf("-Werror", "-Xlint:all,-fallthrough,-serial"))
    options.errorprone {
        enable("DefaultLocale")
        error("RequireExplicitNullMarking")
        error("WildcardImport")
        nullaway {
            knownInitializers.addAll(
                "jakarta.servlet.Servlet.init",
                "jakarta.servlet.GenericServlet.init",
                "jakarta.servlet.Filter.init",
                "jakarta.servlet.GenericFilter.init",
            )
        }
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

tasks.withType<Javadoc>().configureEach {
    isFailOnError = true
    (options as StandardJavadocDocletOptions).apply {
        noTimestamp()
        quiet()
        use()
        addStringOption("-release", java.sourceCompatibility.majorVersion)
        addBooleanOption("Xdoclint:-missing", true)
        addStringOption("-link-modularity-mismatch", "info")
        val relativeRootDir = rootDir.toRelativeString(projectDir)
        linksOffline(
            "https://jakarta.ee/specifications/servlet/6.0/apidocs/",
            "$relativeRootDir/build-logic/src/javadoc-link/servlet/")
        linksOffline(
            "https://jakarta.ee/specifications/restful-ws/4.0/apidocs/",
            "$relativeRootDir/build-logic/src/javadoc-link/restful-ws/")
        linksOffline(
            "https://jakarta.ee/specifications/annotations/2.1/apidocs/",
            "$relativeRootDir/build-logic/src/javadoc-link/jakarta.annotation/")
        linksOffline(
            "https://jspecify.dev/docs/api/",
            "$relativeRootDir/build-logic/src/javadoc-link/jspecify/")
        linksOffline(
            "https://errorprone.info/api/latest/",
            "$relativeRootDir/build-logic/src/javadoc-link/errorprone/")
        linksOffline(
            "https://javadoc.io/doc/com.nimbusds/oauth2-oidc-sdk/latest/",
            "$relativeRootDir/build-logic/src/javadoc-link/oauth2-oidc-sdk/")
        linksOffline(
            "https://javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/latest/",
            "$relativeRootDir/build-logic/src/javadoc-link/nimbus-jose-jwt/")
        linksOffline(
            "https://javadoc.io/doc/com.github.ben-manes.caffeine/caffeine/latest/",
            "$relativeRootDir/build-logic/src/javadoc-link/caffeine/")
        linksOffline(
            "https://javadoc.io/doc/net.ltgt.oauth/oauth-common/$version/",
            "$relativeRootDir/build-logic/src/javadoc-link/oauth-common/")
        tags(
            "implSpec:a:Implementation Specification:",
        )
    }
}

spotless {
    java {
        removeUnusedImports()
        forbidWildcardImports()
        forbidModuleImports()
        googleJavaFormat(project.versionCatalogs.named("libs").findVersion("googleJavaFormat").orElseThrow().requiredVersion).reorderImports(true)
        licenseHeaderFile(rootProject.isolated.projectDirectory.file("LICENSE.header"))
    }
}
