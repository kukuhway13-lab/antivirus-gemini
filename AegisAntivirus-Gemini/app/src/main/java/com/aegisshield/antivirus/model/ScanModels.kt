package com.aegisshield.antivirus.model

enum class ThreatLevel(val label: String, val colorHex: Long) {
    SAFE("Aman", 0xFF00E676),
    LOW_RISK("Risiko Rendah", 0xFF29B6F6),
    SUSPICIOUS("Mencurigakan", 0xFFFFB300),
    MALWARE_CRITICAL("Bahaya / Malware", 0xFFFF1744)
}

enum class ComparisonStatus(val label: String, val description: String) {
    AGREE_SAFE("Konsensus: Aman", "Mesin Lokal & Gemini AI sepakat aplikasi ini bersih."),
    AGREE_MALWARE("Konsensus: Berbahaya!", "Kedua mesin mendeteksi ancaman berbahaya nyata."),
    GEMINI_DETECTED_HIDDEN_THREAT("Gemini Menemukan Ancaman Baru!", "Mesin lokal mengira aman, namun Gemini AI mendeteksi teknik penghindaran canggih."),
    LOCAL_FALSE_POSITIVE("Kemungkinan False Positive", "Gemini AI mengklarifikasi izin aplikasi sah dan wajar untuk fungsinya."),
    PENDING_AI("Menunggu Analisis AI", "Baru selesai dipindai oleh mesin lokal.")
}

data class AppSecurityProfile(
    val appName: String,
    val packageName: String,
    val versionName: String,
    val isSystemApp: Boolean,
    val apkPath: String,
    val fileSizeMb: Double,
    val sha256: String,
    val requestedPermissions: List<String>,
    val dangerousPermissions: List<String>,
    val hasAccessibilityAbuse: Boolean = false,
    val hasOverlayPermission: Boolean = false,
    val hasSmsIntercept: Boolean = false,
    val hasHiddenLauncher: Boolean = false,
    val localThreatLevel: ThreatLevel = ThreatLevel.SAFE,
    val localScore: Int = 0,
    val localReasons: List<String> = emptyList(),
    var geminiAnalysis: GeminiAnalysis? = null,
    var isAnalyzingWithGemini: Boolean = false
) {
    val comparisonStatus: ComparisonStatus
        get() {
            val gemini = geminiAnalysis ?: return ComparisonStatus.PENDING_AI
            val isLocalDanger = localThreatLevel == ThreatLevel.SUSPICIOUS || localThreatLevel == ThreatLevel.MALWARE_CRITICAL
            val isGeminiDanger = gemini.verdict == ThreatLevel.SUSPICIOUS || gemini.verdict == ThreatLevel.MALWARE_CRITICAL

            return when {
                !isLocalDanger && !isGeminiDanger -> ComparisonStatus.AGREE_SAFE
                isLocalDanger && isGeminiDanger -> ComparisonStatus.AGREE_MALWARE
                !isLocalDanger && isGeminiDanger -> ComparisonStatus.GEMINI_DETECTED_HIDDEN_THREAT
                isLocalDanger && !isGeminiDanger -> ComparisonStatus.LOCAL_FALSE_POSITIVE
                else -> ComparisonStatus.AGREE_SAFE
            }
        }
}

data class GeminiAnalysis(
    val verdict: ThreatLevel,
    val threatScore: Int, // 0 - 100
    val threatFamily: String,
    val aiAnalysisDetail: String,
    val suspiciousFactors: List<String>,
    val actionRecommendation: String,
    val securityAdvice: String,
    val modelUsed: String = "gemini-1.5-flash",
    val analyzedAt: Long = System.currentTimeMillis()
)

data class ScanSummary(
    val totalApps: Int = 0,
    val safeCount: Int = 0,
    val suspiciousCount: Int = 0,
    val malwareCount: Int = 0,
    val aiAuditedCount: Int = 0,
    val discrepanciesCount: Int = 0
)
