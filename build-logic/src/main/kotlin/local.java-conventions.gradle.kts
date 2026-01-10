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
    }
}

dependencies {
    errorprone(project.versionCatalogs.named("libs").findBundle("errorprone").orElseThrow())
}

nullaway {
    onlyNullMarked = true
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
        nullaway {
            isJSpecifyMode = true
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
        links(
            "https://jakarta.ee/specifications/servlet/6.0/apidocs/",
            "https://checkerframework.org/api/",
            "https://errorprone.info/api/latest/"
        )
        // Nimbus OAuth SDK javadoc doesn't include a package-list
        linksOffline(
            "https://javadoc.io/doc/com.nimbusds/oauth2-oidc-sdk/latest/",
            rootProject.file("build-logic/src/javadoc-link/nimbusds-oidc-sdk/").toRelativeString(projectDir)
        )
    }
}

spotless {
    java {
        googleJavaFormat(project.versionCatalogs.named("libs").findVersion("googleJavaFormat").orElseThrow().requiredVersion)
    }
}
