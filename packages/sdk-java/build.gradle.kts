description = "Warrant client SDK for agents (proof-of-possession signing, typed decisions) and the warrant CLI."

val cli: SourceSet by sourceSets.creating {
    compileClasspath += sourceSets.main.get().output
    runtimeClasspath += sourceSets.main.get().output
}

configurations[cli.implementationConfigurationName].extendsFrom(configurations.implementation.get())
configurations[cli.runtimeOnlyConfigurationName].extendsFrom(configurations.runtimeOnly.get())

dependencies {
    api(project(":warrant-core"))
    "cliImplementation"(platform("org.springframework.boot:spring-boot-dependencies:3.3.13"))
    "cliImplementation"(project(":policy-dsl"))
    testImplementation("org.junit.jupiter:junit-jupiter-params")
}

val cliJar by tasks.registering(Jar::class) {
    description = "Self-contained warrant CLI: audit trace/verify/export, policy lint/test, warrant issue/revoke, keygen."
    group = "build"
    archiveFileName.set("warrant-cli.jar")
    manifest { attributes["Main-Class"] = "io.warrant.sdk.cli.WarrantCli" }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(cli.output)
    from(sourceSets.main.get().output)
    dependsOn(configurations[cli.runtimeClasspathConfigurationName])
    from({ configurations[cli.runtimeClasspathConfigurationName].filter { it.name.endsWith(".jar") }.map { zipTree(it) } }) {
        exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/versions/*/module-info.class")
    }
}

tasks.named("assemble") { dependsOn(cliJar) }

dependencies {
    testImplementation(testFixtures(project(":warrant-core")))
}
