plugins {
    kotlin("jvm") version "2.1.21"
}

group = "com.hxdatalock"
version = "0.1.0"

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.81")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.81")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
}

sourceSets {
    create("examples") {
        kotlin.srcDir("../../examples/kotlin")
        compileClasspath += sourceSets["main"].output + configurations["runtimeClasspath"]
        runtimeClasspath += output + compileClasspath
    }
}

tasks.test {
    useJUnitPlatform()
}

tasks.register<JavaExec>("runOpenExample") {
    group = "examples"
    dependsOn("compileExamplesKotlin")
    classpath = sourceSets["examples"].runtimeClasspath
    mainClass.set("OpenEnvelopeKt")
    args = (project.findProperty("exampleArgs") as String? ?: "").split("|").filter { it.isNotEmpty() }
}

tasks.register<JavaExec>("runLockExample") {
    group = "examples"
    dependsOn("compileExamplesKotlin")
    classpath = sourceSets["examples"].runtimeClasspath
    mainClass.set("LockEnvelopeKt")
    args = (project.findProperty("exampleArgs") as String? ?: "").split("|").filter { it.isNotEmpty() }
}
