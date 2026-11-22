plugins {
    id("org.springframework.boot") version "3.3.13" apply false
    id("io.spring.dependency-management") version "1.1.7" apply false
}

val springBootVersion = "3.3.13"
val testcontainersVersion = "1.20.6"

subprojects {
    apply(plugin = "java-library")

    group = "io.warrant"
    version = "1.0.0"

    extensions.configure<JavaPluginExtension> {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(21))
        }
    }

    dependencies {
        "implementation"(platform("org.springframework.boot:spring-boot-dependencies:$springBootVersion"))
        "testImplementation"(platform("org.springframework.boot:spring-boot-dependencies:$springBootVersion"))
        "testImplementation"(platform("org.testcontainers:testcontainers-bom:$testcontainersVersion"))
        "testImplementation"("org.junit.jupiter:junit-jupiter")
        "testImplementation"("org.assertj:assertj-core")
        "testRuntimeOnly"("org.junit.platform:junit-platform-launcher")
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.compilerArgs.addAll(listOf("-Xlint:all,-serial,-processing,-this-escape,-try", "-Werror", "-parameters"))
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        maxHeapSize = "1g"
        testLogging {
            events("failed")
            exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        }
        systemProperty("java.awt.headless", "true")
        // Docker Engine 29 rejects API versions below 1.44; Testcontainers 1.20.x negotiates an older one.
        systemProperty("api.version", System.getenv("DOCKER_API_VERSION") ?: "1.44")
    }

    // The adversarial suite is a separate, always-run CI gate. Every test tagged
    // "adversarial" is an attack that must fail in a specified way.
    tasks.register<Test>("adversarialTest") {
        description = "Runs the adversarial security suite (blocking, never skipped)."
        group = "verification"
        val testSourceSet = project.extensions.getByType<SourceSetContainer>()["test"]
        testClassesDirs = testSourceSet.output.classesDirs
        classpath = testSourceSet.runtimeClasspath
        useJUnitPlatform { includeTags("adversarial") }
        outputs.upToDateWhen { false }
    }
}
