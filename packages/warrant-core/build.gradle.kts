plugins {
    `java-test-fixtures`
}

description = "Shared contracts and cryptographic primitives: warrant object, verifier, canonical JSON, decision types."

dependencies {
    api("com.fasterxml.jackson.core:jackson-databind")
    api("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")
    testFixturesImplementation(platform("org.springframework.boot:spring-boot-dependencies:3.3.13"))
    testImplementation("org.junit.jupiter:junit-jupiter-params")
}
