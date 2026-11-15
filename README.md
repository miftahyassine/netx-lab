# NETX LAB

Portable Android networking & Wi-Fi security laboratory (Kotlin, Jetpack Compose, Material 3, MVVM, Hilt, Room, DataStore, Coroutines/Flow).

## Build
* **GitHub:** push the repo → *Actions → Android CI*. It runs unit tests, builds the debug APK and uploads it as artifact `netx-lab-debug-apk`.
* **Locally:** open in Android Studio (Koala+, JDK 17) and run `./gradlew assembleDebug` (or `.\gradlew.bat assembleDebug` on Windows).
* **Release signing:** add secrets `KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`, then run the workflow manually with *build_release* ticked.

## Compatibility
Min SDK 26 (Android 8.0), target/compile SDK 34. No root required.