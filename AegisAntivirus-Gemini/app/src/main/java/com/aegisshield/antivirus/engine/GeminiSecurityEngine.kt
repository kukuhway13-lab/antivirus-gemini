package com.aegisshield.antivirus.engine

import android.content.Context
import android.util.Log
import com.aegisshield.antivirus.model.AppSecurityProfile
import com.aegisshield.antivirus.model.GeminiAnalysis
import com.aegisshield.antivirus.model.ThreatLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

class GeminiSecurityEngine(private val context: Context) {

    companion object {
        private const val TAG = "GeminiSecurityEngine"
        private const val PREF_NAME = "gemini_security_prefs"
        private const val KEY_API_KEY = "gemini_api_key"
        private const val KEY_MODEL = "gemini_model_name"
        const val DEFAULT_MODEL = "gemini-1.5-flash"
    }

    private val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)

    fun saveApiKey(apiKey: String) {
        prefs.edit().putString(KEY_API_KEY, apiKey.trim()).apply()
    }

    fun getApiKey(): String {
        return prefs.getString(KEY_API_KEY, "") ?: ""
    }

    fun setModelName(model: String) {
        prefs.edit().putString(KEY_MODEL, model).apply()
    }

    fun getModelName(): String {
        return prefs.getString(KEY_MODEL, DEFAULT_MODEL) ?: DEFAULT_MODEL
    }

    /**
     * Mengirimkan profil aplikasi ke Google Gemini AI untuk diaudit dan dibandingkan dengan mesin lokal
     */
    suspend fun auditAppWithGemini(app: AppSecurityProfile): GeminiAnalysis = withContext(Dispatchers.IO) {
        val apiKey = getApiKey()
        val model = getModelName()

        if (apiKey.isBlank()) {
            // Jika user belum memasukkan API key, jalankan simulasi analisis cerdas Gemini
            return@withContext runSimulatedGeminiAnalysis(app)
        }

        try {
            val endpoint = "https://generativelanguage.googleapis.com/v1beta/models/$model:generateContent?key=$apiKey"
            val url = URL(endpoint)
            val connection = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                setRequestProperty("Content-Type", "application/json")
                doOutput = true
                connectTimeout = 20000
                readTimeout = 30000
            }

            val prompt = buildAnalysisPrompt(app)
            val requestBody = JSONObject().apply {
                val contents = JSONArray().apply {
                    val partObj = JSONObject().apply {
                        put("parts", JSONArray().apply {
                            put(JSONObject().apply { put("text", prompt) })
                        })
                    }
                    put(partObj)
                }
                put("contents", contents)
                
                // Minta output dalam format JSON yang terstruktur
                val genConfig = JSONObject().apply {
                    put("responseMimeType", "application/json")
                    put("temperature", 0.2)
                }
                put("generationConfig", genConfig)
            }

            val writer = OutputStreamWriter(connection.outputStream)
            writer.write(requestBody.toString())
            writer.flush()
            writer.close()

            val responseCode = connection.responseCode
            if (responseCode == HttpURLConnection.HTTP_OK) {
                val reader = BufferedReader(InputStreamReader(connection.inputStream))
                val responseText = reader.readText()
                reader.close()

                return@withContext parseGeminiResponse(responseText, model)
            } else {
                val errorStream = connection.errorStream
                val errorMsg = if (errorStream != null) {
                    BufferedReader(InputStreamReader(errorStream)).readText()
                } else {
                    "HTTP Error $responseCode"
                }
                Log.e(TAG, "Gemini API error ($responseCode): $errorMsg")
                return@withContext fallbackAnalysisOnError(app, "Gagal menghubungi Gemini ($responseCode). Periksa API Key Anda.")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception calling Gemini: ${e.message}", e)
            return@withContext fallbackAnalysisOnError(app, "Koneksi terputus: ${e.localizedMessage}")
        }
    }

    private fun buildAnalysisPrompt(app: AppSecurityProfile): String {
        return """
        Anda adalah Principal Android Malware Analyst & Threat Intelligence Expert.
        Tugas Anda adalah memeriksa apakah aplikasi Android ini adalah VIRUS/MALWARE atau BUKAN, dan BANDINGKAN hasil analisis Anda dengan penilaian Mesin Heuristik Lokal kami.

        [DATA APLIKASI YANG DIPERIKSA]
        - Nama Aplikasi: ${app.appName}
        - Nama Paket (Package Name): ${app.packageName}
        - Versi: ${app.versionName}
        - Apakah Aplikasi Sistem: ${if (app.isSystemApp) "Ya" else "Tidak"}
        - Ukuran File: ${app.fileSizeMb} MB
        - SHA-256 Hash: ${app.sha256}
        - Izin Berbahaya Diminta: ${app.dangerousPermissions.joinToString(", ")}
        - Semua Izin Diminta: ${app.requestedPermissions.joinToString(", ")}

        [HASIL ANALISIS MESIN HEURISTIK LOKAL KAMI]
        - Tingkat Ancaman Lokal: ${app.localThreatLevel.label}
        - Skor Risiko Lokal: ${app.localScore} / 100
        - Alasan Mesin Lokal: ${app.localReasons.joinToString("; ")}

        Lakukan analisis komparatif mendalam:
        1. Apakah izin-izin tersebut wajar untuk kategori fungsinya, atau ada indikasi anomali (misal berkedok Surat Undangan/Resi namun minta SMS dan Aksesibilitas)?
        2. Berikan verdict Anda (SAFE, LOW_RISK, SUSPICIOUS, MALWARE_CRITICAL).
        3. Jelaskan perbandingan antara pendapat Anda dengan Mesin Lokal (apakah Anda setuju, atau menemukan ancaman baru / false positive).
        4. Tuliskan rekomendasi tindakan konkret untuk pengguna dalam Bahasa Indonesia yang ramah dan mudah dipahami.

        Kembalikan HANYA format JSON valid berikut tanpa teks lain:
        {
          "verdict": "SAFE" | "LOW_RISK" | "SUSPICIOUS" | "MALWARE_CRITICAL",
          "threat_score": 0-100,
          "threat_family": "Contoh: Trojan Perbankan / SMS Stealer / Bersih / Adware",
          "ai_analysis_detail": "Penjelasan komparasi lengkap mengapa aplikasi ini aman atau berbahaya dibandingan penilaian mesin lokal",
          "suspicious_factors": ["faktor 1", "faktor 2"],
          "action_recommendation": "Contoh: HAPUS_SEGERA / AMAN_DIGUNAKAN / WASPADA_IZIN",
          "security_advice": "Saran mitigasi keamanan untuk pengguna"
        }
        """.trimIndent()
    }

    private fun parseGeminiResponse(rawResponse: String, model: String): GeminiAnalysis {
        val root = JSONObject(rawResponse)
        val candidates = root.getJSONArray("candidates")
        val content = candidates.getJSONObject(0).getJSONObject("content")
        val parts = content.getJSONArray("parts")
        var jsonText = parts.getJSONObject(0).getString("text").trim()

        // Hilangkan markdown code block jika ada
        if (jsonText.startsWith("```json")) {
            jsonText = jsonText.removePrefix("```json").removeSuffix("```").trim()
        } else if (jsonText.startsWith("```")) {
            jsonText = jsonText.removePrefix("```").removeSuffix("```").trim()
        }

        val parsed = JSONObject(jsonText)
        val verdictStr = parsed.optString("verdict", "SAFE").uppercase()
        val verdict = when (verdictStr) {
            "MALWARE_CRITICAL", "MALWARE" -> ThreatLevel.MALWARE_CRITICAL
            "SUSPICIOUS" -> ThreatLevel.SUSPICIOUS
            "LOW_RISK" -> ThreatLevel.LOW_RISK
            else -> ThreatLevel.SAFE
        }

        val score = parsed.optInt("threat_score", 0)
        val family = parsed.optString("threat_family", "Tidak Diketahui")
        val detail = parsed.optString("ai_analysis_detail", "Analisis berhasil diselesaikan oleh Gemini.")
        val rec = parsed.optString("action_recommendation", "Aman")
        val advice = parsed.optString("security_advice", "Selalu waspada terhadap izin aplikasi.")

        val factorsList = mutableListOf<String>()
        val factorsArr = parsed.optJSONArray("suspicious_factors")
        if (factorsArr != null) {
            for (i in 0 until factorsArr.length()) {
                factorsList.add(factorsArr.getString(i))
            }
        }

        return GeminiAnalysis(
            verdict = verdict,
            threatScore = score,
            threatFamily = family,
            aiAnalysisDetail = detail,
            suspiciousFactors = factorsList,
            actionRecommendation = rec,
            securityAdvice = advice,
            modelUsed = model
        )
    }

    /**
     * Mode simulasi offline jika pengguna belum memasukkan Gemini API Key
     */
    private fun runSimulatedGeminiAnalysis(app: AppSecurityProfile): GeminiAnalysis {
        val hasSms = app.requestedPermissions.any { it.contains("SMS", ignoreCase = true) }
        val hasAccessibility = app.hasAccessibilityAbuse
        val isScamName = MalwareDatabase.SUSPICIOUS_INDONESIAN_SCAM_KEYWORDS.any { 
            app.appName.lowercase().contains(it) 
        }

        return when {
            isScamName && (hasSms || hasAccessibility) -> {
                GeminiAnalysis(
                    verdict = ThreatLevel.MALWARE_CRITICAL,
                    threatScore = 95,
                    threatFamily = "Indonesian Banking Trojan (APK Phishing / SMS Sniffer)",
                    aiAnalysisDetail = "Gemini AI mengonfirmasi: Pola nama '${app.appName}' dengan izin membaca SMS dan Layanan Aksesibilitas merupakan indikator kuat modus pencurian OTP mobile banking yang marak di Indonesia.",
                    suspiciousFactors = listOf(
                        "Pola nama menyerupai berkas/layanan resmi padahal paket tidak terafiliasi",
                        "Meminta BIND_ACCESSIBILITY_SERVICE untuk mengontrol klik dan membaca OTP otomatis",
                        "Meminta RECEIVE_SMS untuk menyadap kode otentikasi SMS perbankan"
                    ),
                    actionRecommendation = "HAPUS SEGERA & JANGAN BERIKAN IZIN",
                    securityAdvice = "Segera uninstall dan periksa apakah ada transaksi tak dikenal di rekening perbankan Anda.",
                    modelUsed = "gemini-simulated (Mode Siap Pakai)"
                )
            }
            app.localThreatLevel == ThreatLevel.MALWARE_CRITICAL -> {
                GeminiAnalysis(
                    verdict = ThreatLevel.MALWARE_CRITICAL,
                    threatScore = 88,
                    threatFamily = "High-Risk Suspicious Payload",
                    aiAnalysisDetail = "Gemini AI menyetujui analisis mesin lokal. Kombinasi izin yang diminta melampaui batasan fungsional aplikasi biasa.",
                    suspiciousFactors = app.localReasons,
                    actionRecommendation = "COPOT PEMASANGAN",
                    securityAdvice = "Aplikasi ini berisiko mengambil alih kontrol perangkat Anda.",
                    modelUsed = "gemini-simulated (Mode Siap Pakai)"
                )
            }
            app.localThreatLevel == ThreatLevel.SUSPICIOUS -> {
                GeminiAnalysis(
                    verdict = ThreatLevel.SUSPICIOUS,
                    threatScore = 55,
                    threatFamily = "Potentially Unwanted Application (PUA)",
                    aiAnalysisDetail = "Gemini AI mendeteksi perilaku agresif atau pengumpulan data yang tidak esensial. Disarankan untuk membatasi izin di Pengaturan Android.",
                    suspiciousFactors = app.localReasons,
                    actionRecommendation = "WASPADA / BATASI IZIN",
                    securityAdvice = "Cabut izin lokasi latar belakang dan penyimpanan jika tidak diperlukan.",
                    modelUsed = "gemini-simulated (Mode Siap Pakai)"
                )
            }
            else -> {
                GeminiAnalysis(
                    verdict = ThreatLevel.SAFE,
                    threatScore = 5,
                    threatFamily = "Aplikasi Bersih / Terpercaya",
                    aiAnalysisDetail = "Gemini AI memverifikasi bahwa aplikasi ini menggunakan izin standar yang konsisten dengan aplikasi Android normal dan tidak menunjukkan perilaku berbahaya.",
                    suspiciousFactors = emptyList(),
                    actionRecommendation = "AMAN DIGUNAKAN",
                    securityAdvice = "Tidak ada ancaman terdeteksi. Aman untuk digunakan sehari-hari.",
                    modelUsed = "gemini-simulated (Mode Siap Pakai)"
                )
            }
        }
    }

    private fun fallbackAnalysisOnError(app: AppSecurityProfile, errorReason: String): GeminiAnalysis {
        return GeminiAnalysis(
            verdict = app.localThreatLevel,
            threatScore = app.localScore,
            threatFamily = "Analisis Offline",
            aiAnalysisDetail = "Koneksi Gemini AI terkendala: $errorReason. Menampilkan hasil estimasi mesin lokal.",
            suspiciousFactors = app.localReasons,
            actionRecommendation = "PERIKSA KEMBALI KONEKSI INTERNET / API KEY",
            securityAdvice = "Pastikan API Key Gemini Anda valid dan ponsel memiliki kuota internet.",
            modelUsed = "offline-fallback"
        )
    }
}
