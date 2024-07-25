import org.jetbrains.intellij.platform.gradle.TestFrameworkType

plugins {
    id("java")
    id("jacoco")
    id("org.sonarqube") version "5.1.0.4882"
    id("org.jetbrains.intellij.platform") version "2.0.0-rc1"
}

group = "com.github.bancolombia"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
    intellijPlatform {
        defaultRepositories()
    }
}

dependencies {
    intellijPlatform {
        intellijIdeaCommunity("2024.1.4")
        pluginVerifier()
        zipSigner()
        instrumentationTools()
        testFramework(TestFrameworkType.Plugin.Java)
        bundledPlugins(
            "com.intellij.java",
            "com.intellij.gradle",
            "org.jetbrains.plugins.gradle",
            "org.intellij.groovy",
            "com.intellij.properties",
            "org.jetbrains.plugins.terminal"
        )
    }

    implementation("com.squareup.okhttp3:okhttp")
    implementation("org.jetbrains:annotations:24.1.0")

    compileOnly("org.projectlombok:lombok:1.18.32")
    annotationProcessor("org.projectlombok:lombok:1.18.32")

    testCompileOnly("org.projectlombok:lombok:1.18.32")
    testAnnotationProcessor("org.projectlombok:lombok:1.18.32")
//
//    testImplementation("org.junit.jupiter:junit-jupiter-engine:5.10.3")
//    testImplementation("org.mockito:mockito-junit-jupiter:5.12.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.mockito:mockito-core:5.12.0")

    implementation(platform("com.squareup.okhttp3:okhttp-bom:4.12.0"))
}

tasks.test {
    useJUnit()
    finalizedBy(tasks.jacocoTestReport)
}

jacoco {
    toolVersion = "0.8.12"
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        xml.outputLocation.set(layout.buildDirectory.file("reports/jacoco.xml"))
        html.required.set(true)
        html.outputLocation.set(layout.buildDirectory.dir("reports/jacocoHtml"))
    }
}

intellijPlatform {
    pluginConfiguration {
        id.set("com.github.bancolombia.devsecops-engine-tools")
        name.set("DevSecOps Engine Tools")
        version.set("1.0-SNAPSHOT")
        description.set("DevSecOps Engine Tools")

        ideaVersion {
            sinceBuild.set("241")
            untilBuild.set("242.*")
        }

        vendor {
            name.set("Bancolombia")
            url.set("https://www.grupobancolombia.com/")
        }
    }

    publishing {
        token.set(System.getenv("PUBLISH_TOKEN"))
    }

    signing {
        certificateChain.set(System.getenv("CERTIFICATE_CHAIN"))
        privateKey.set(System.getenv("PRIVATE_KEY"))
        password.set(System.getenv("PRIVATE_KEY_PASSWORD"))
    }
}

sonar {
    properties {
        property("sonar.sourceEncoding", "UTF-8")
        property("sonar.projectKey", "bancolombia_devsecops-engine-tool-ide-extension-intellij")
        property("sonar.organization", "grupo-bancolombia")
        property("sonar.host.url", "https://sonarcloud.io/")
        property("sonar.sources", "src/main")
        property("sonar.tests", "src/test")
        property("sonar.java.binaries", "build/classes")
        property("sonar.junit.reportPaths", "build/test-results/test")
        property("sonar.java.coveragePlugin", "jacoco")
        property("sonar.coverage.jacoco.xmlReportPaths", "${rootDir}/build/reports/jacoco/jacoco.xml")
        property("sonar.exclusions", ".github/**")
    }
}

tasks.wrapper {
    gradleVersion = "8.9"
}
