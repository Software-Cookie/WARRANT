plugins {
    id("org.springframework.boot")
    id("io.spring.dependency-management")
}

description = "Control plane: policy, warrant issuance, approvals, audit chain, admin API."

dependencies {
    implementation(project(":warrant-core"))
    implementation(project(":policy-dsl"))
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    implementation("org.springframework.boot:spring-boot-starter-data-redis")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-mail")
    implementation("org.flywaydb:flyway-core")
    implementation("org.flywaydb:flyway-database-postgresql")
    runtimeOnly("org.postgresql:postgresql")
    runtimeOnly("com.google.cloud.sql:postgres-socket-factory:1.31.0")

    testImplementation(testFixtures(project(":warrant-core")))
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.testcontainers:junit-jupiter")
    testImplementation("org.testcontainers:postgresql")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
}

tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
    archiveFileName.set("control-plane.jar")
}

tasks.named<Jar>("jar") {
    enabled = false
}
