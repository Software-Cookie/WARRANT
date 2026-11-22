description = "Warrant policy language: lexer, parser, compiler to a JSON decision tree, evaluator and test runner."

dependencies {
    api(project(":warrant-core"))
    testImplementation("org.junit.jupiter:junit-jupiter-params")
}

val cliJar by tasks.registering(Jar::class) {
    description = "Self-contained policy CLI (lint, test, compile)."
    group = "build"
    archiveBaseName.set("policy-cli")
    manifest { attributes["Main-Class"] = "io.warrant.policy.cli.PolicyCli" }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(sourceSets.main.get().output)
    dependsOn(configurations.runtimeClasspath)
    from({ configurations.runtimeClasspath.get().filter { it.name.endsWith(".jar") }.map { zipTree(it) } }) {
        exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/versions/*/module-info.class")
    }
}

tasks.named("assemble") { dependsOn(cliJar) }
