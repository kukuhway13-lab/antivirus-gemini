# Proguard rules for Aegis Gemini Antivirus
-keepattributes *Annotation*
-keepclassmembers class * {
    @org.json.* <fields>;
    @org.json.* <methods>;
}
