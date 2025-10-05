plugins {
    id("local.common-conventions")
    id("local.maven-publish-conventions")
    `java-platform`
}

dependencies {
    constraints {
        api(projects.oauthCommon)
        api(projects.oauthServlets)
        api(projects.oauthRs)
    }
}

mavenPublishing {
    pom {
        name = "OAuth Servlets BOM"
        description = "Bill of Materials for OAuth Servlets"
    }
}
