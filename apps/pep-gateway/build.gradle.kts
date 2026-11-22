plugins {
    id("org.springframework.boot")
    id("io.spring.dependency-management")
}

description = "Policy enforcement point: verifies warrants, decides L0/L1/L2, injects credentials, forwards, emits audit."

dependencies {
    implementation(project(":warrant-core"))
    implementation(project(":policy-dsl"))
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-data-redis")
    implementation("org.springframework.boot:spring-boot-starter-actuator")

    testImplementation(testFixtures(project(":warrant-core")))
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.testcontainers:junit-jupiter")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
}

tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
    archiveFileName.set("pep-gateway.jar")
}

tasks.named<Jar>("jar") {
    enabled = false
}
