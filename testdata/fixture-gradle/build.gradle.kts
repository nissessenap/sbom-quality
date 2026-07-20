// Small-but-real Java fixture (Gradle, Kotlin DSL) for the sbom-quality bench.
// Same deps as testdata/fixture-maven so merge/dedup/enrich are exercised, and
// builds its container via Jib (`./gradlew jibBuildTar` -> build/jib-image.tar,
// no Docker daemon or registry needed). Wrapper pins Gradle; see README.
plugins {
    application
    id("com.google.cloud.tools.jib") version "3.5.4"
}

repositories {
    mavenCentral()
}

java {
    // Bytecode 17 on whatever JDK (>=17) runs the build; no toolchain
    // auto-provisioning, so the fixture builds anywhere the JDK is >=17.
    // Jib reads targetCompatibility to match the 17-jre base image.
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation("com.google.guava:guava:33.4.8-jre")
    implementation("org.apache.commons:commons-lang3:3.17.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.18.2")
}

application {
    mainClass = "com.example.App"
}

jib {
    from {
        // R3 (#38): Jib's default is a full-OS eclipse-temurin; pin it explicitly.
        image = "eclipse-temurin:17-jre"
    }
    to {
        image = "fixture-gradle"
    }
}
