package com.aegisshield.antivirus.engine

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import com.aegisshield.antivirus.model.AppSecurityProfile
import com.aegisshield.antivirus.model.ThreatLevel
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

class LocalHeuristicEngine(private val context: Context) {

    /**
     * Memindai semua aplikasi terpasang di perangkat
     */
    fun scanAllInstalledApps(includeSystemApps: Boolean = false): List<AppSecurityProfile> {
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(
            PackageManager.GET_PERMISSIONS or 
            PackageManager.GET_SERVICES or 
            PackageManager.GET_RECEIVERS
        )

        val results = mutableListOf<AppSecurityProfile>()
        for (pkg in packages) {
            val isSystem = (pkg.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            if (!includeSystemApps && isSystem) {
                continue
            }
            results.add(analyzePackage(pkg, pm))
        }

        // Urutkan berdasarkan tingkat risiko tertinggi terlebih dahulu
        return results.sortedByDescending { it.localScore }
    }

    /**
     * Menganalisis file APK mandiri (misal yang baru diunduh di folder Downloads)
     */
    fun scanApkFile(apkFile: File): AppSecurityProfile? {
        val pm = context.packageManager
        val pkg = pm.getPackageArchiveInfo(
            apkFile.absolutePath,
            PackageManager.GET_PERMISSIONS or 
            PackageManager.GET_SERVICES or 
            PackageManager.GET_RECEIVERS
        ) ?: return null

        pkg.applicationInfo.sourceDir = apkFile.absolutePath
        pkg.applicationInfo.publicSourceDir = apkFile.absolutePath

        return analyzePackage(pkg, pm, apkFile)
    }

    /**
     * Algoritma Heuristik Penilaian Risiko
     */
    fun analyzePackage(pkg: PackageInfo, pm: PackageManager, standaloneFile: File? = null): AppSecurityProfile {
        val appName = try {
            pkg.applicationInfo.loadLabel(pm).toString()
        } catch (e: Exception) {
            pkg.packageName
        }

        val isSystem = (pkg.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val requestedPerms = pkg.requestedPermissions?.toList() ?: emptyList()
        val dangerousPerms = requestedPerms.filter { MalwareDatabase.PERMISSION_RISK_WEIGHTS.containsKey(it) }

        val hasAccessibility = requestedPerms.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
        val hasOverlay = requestedPerms.contains("android.permission.SYSTEM_ALERT_WINDOW")
        val hasSms = requestedPerms.any { it.contains("SMS", ignoreCase = true) }
        val hasBoot = requestedPerms.contains("android.permission.RECEIVE_BOOT_COMPLETED")
        val hasAdmin = requestedPerms.contains("android.permission.BIND_DEVICE_ADMIN")

        val apkPath = standaloneFile?.absolutePath ?: pkg.applicationInfo.sourceDir ?: ""
        val file = standaloneFile ?: File(apkPath)
        val fileSizeMb = if (file.exists()) file.length() / (1024.0 * 1024.0) else 0.0
        val sha256 = if (file.exists()) calculateSha256(file) else "N/A"

        var score = 0
        val reasons = mutableListOf<String>()

        // 1. Hitung bobot dari izin berbahaya
        for (perm in dangerousPerms) {
            val weight = MalwareDatabase.PERMISSION_RISK_WEIGHTS[perm] ?: 5
            score += weight
        }

        // 2. Deteksi Pola Trojan Perbankan Indonesia (Surat Undangan APK / Resi J&T / APK Phishing)
        val lowerName = appName.lowercase()
        val isNameScamKeyword = MalwareDatabase.SUSPICIOUS_INDONESIAN_SCAM_KEYWORDS.any { lowerName.contains(it) }

        if (isNameScamKeyword && (hasSms || hasAccessibility || hasOverlay)) {
            score += 65
            reasons.add("WASPADA: Nama aplikasi berkedok dokumen/kurir/pajak namun meminta izin membaca SMS / Aksesibilitas (Pola Trojan Perbankan APK)")
        }

        // 3. Deteksi Kombinasi Berbahaya (Malicious Permission Combos)
        if (hasOverlay && hasSms && hasBoot) {
            score += 45
            reasons.add("Kombinasi Overlay (tampilan palsu) + Sadap SMS + Auto-Start saat HP nyala")
        }

        if (hasAccessibility) {
            score += 35
            reasons.add("Meminta Hak Aksesibilitas Penuh (Dapat mengklik otomatis & merekam layar)")
        }

        if (hasAdmin) {
            score += 30
            reasons.add("Meminta Hak Device Admin (Dapat mengunci HP dan sulit dicopot)")
        }

        // 4. Deteksi Virus Uji EICAR
        if (sha256.equals(MalwareDatabase.EICAR_SHA256, ignoreCase = true)) {
            score = 100
            reasons.add("TERDETEKSI: Sampel Virus Standar Uji EICAR")
        }

        // Kalibrasi jika aplikasi sistem resmi
        if (isSystem) {
            score = (score * 0.25).toInt()
        }

        score = score.coerceIn(0, 100)

        val threatLevel = when {
            score >= 70 -> ThreatLevel.MALWARE_CRITICAL
            score >= 40 -> ThreatLevel.SUSPICIOUS
            score >= 15 -> ThreatLevel.LOW_RISK
            else -> ThreatLevel.SAFE
        }

        return AppSecurityProfile(
            appName = appName,
            packageName = pkg.packageName,
            versionName = pkg.versionName ?: "1.0",
            isSystemApp = isSystem,
            apkPath = apkPath,
            fileSizeMb = String.format("%.2f", fileSizeMb).toDoubleOrNull() ?: 0.0,
            sha256 = sha256,
            requestedPermissions = requestedPerms,
            dangerousPermissions = dangerousPerms,
            hasAccessibilityAbuse = hasAccessibility,
            hasOverlayPermission = hasOverlay,
            hasSmsIntercept = hasSms,
            hasHiddenLauncher = false,
            localThreatLevel = threatLevel,
            localScore = score,
            localReasons = reasons
        )
    }

    private fun calculateSha256(file: File): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val fis = FileInputStream(file)
            val buffer = ByteArray(8192)
            var bytesRead: Int
            while (fis.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
            fis.close()
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            "error_calculating_hash"
        }
    }
}
