// SHAIP / SHAIP VPN Android client.
//
// Repositories are ordered to survive a rate-limited Maven Central: Google's
// GCS-backed Central mirror is tried first (it does not throttle), then the
// Google Android Maven repo, then Central itself as a last resort.
pluginManagement {
    repositories {
        maven { url = uri("https://maven-central.storage-download.googleapis.com/maven2/") }
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        gradlePluginPortal()
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven { url = uri("https://maven-central.storage-download.googleapis.com/maven2/") }
        google()
        mavenCentral()
    }
}

rootProject.name = "shaip-android"
include(":app")
