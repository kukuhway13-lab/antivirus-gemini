package com.aegisshield.antivirus

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.lifecycleScope
import com.aegisshield.antivirus.engine.GeminiSecurityEngine
import com.aegisshield.antivirus.engine.LocalHeuristicEngine
import com.aegisshield.antivirus.engine.MalwareDatabase
import com.aegisshield.antivirus.model.AppSecurityProfile
import com.aegisshield.antivirus.model.ComparisonStatus
import com.aegisshield.antivirus.model.GeminiAnalysis
import com.aegisshield.antivirus.model.ThreatLevel
import com.aegisshield.antivirus.ui.theme.*
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private lateinit var localEngine: LocalHeuristicEngine
    private lateinit var geminiEngine: GeminiSecurityEngine

    private var appList = mutableStateListOf<AppSecurityProfile>()
    private var isScanning = mutableStateOf(false)
    private var scanProgress = mutableStateOf(0f)
    private var currentScanningApp = mutableStateOf("")
    private var selectedAppForDetail = mutableStateOf<AppSecurityProfile?>(null)
    private var selectedTab = mutableStateOf(0) // 0: Dashboard, 1: Hasil & Komparasi, 2: Pengaturan

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        localEngine = LocalHeuristicEngine(this)
        geminiEngine = GeminiSecurityEngine(this)

        setContent {
            AegisAntivirusTheme {
                MainAntivirusApp()
            }
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun MainAntivirusApp() {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Shield,
                                contentDescription = null,
                                tint = NeonCyan,
                                modifier = Modifier.size(28.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Column {
                                Text(
                                    text = "AEGIS GEMINI ANTIVIRUS",
                                    fontSize = 17.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = TextPrimary,
                                    fontFamily = FontFamily.Monospace
                                )
                                Text(
                                    text = "Dual-Engine: Heuristic + Gemini AI",
                                    fontSize = 11.sp,
                                    color = NeonGreen
                                )
                            }
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = CyberSurfaceDark
                    )
                )
            },
            bottomBar = {
                NavigationBar(
                    containerColor = CyberSurfaceDark
                ) {
                    NavigationBarItem(
                        selected = selectedTab.value == 0,
                        onClick = { selectedTab.value = 0 },
                        icon = { Icon(Icons.Default.Security, contentDescription = "Pindai") },
                        label = { Text("Pindai") },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = NeonCyan,
                            selectedTextColor = NeonCyan,
                            unselectedIconColor = TextSecondary,
                            unselectedTextColor = TextSecondary
                        )
                    )
                    NavigationBarItem(
                        selected = selectedTab.value == 1,
                        onClick = { selectedTab.value = 1 },
                        icon = { 
                            BadgedBox(
                                badge = {
                                    val threatCount = appList.count { it.localThreatLevel == ThreatLevel.MALWARE_CRITICAL || it.localThreatLevel == ThreatLevel.SUSPICIOUS }
                                    if (threatCount > 0) {
                                        Badge(containerColor = NeonRed) {
                                            Text("$threatCount", color = Color.White)
                                        }
                                    }
                                }
                            ) {
                                Icon(Icons.Default.CompareArrows, contentDescription = "Komparasi") 
                            }
                        },
                        label = { Text("Komparasi AI") },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = NeonCyan,
                            selectedTextColor = NeonCyan,
                            unselectedIconColor = TextSecondary,
                            unselectedTextColor = TextSecondary
                        )
                    )
                    NavigationBarItem(
                        selected = selectedTab.value == 2,
                        onClick = { selectedTab.value = 2 },
                        icon = { Icon(Icons.Default.Settings, contentDescription = "Pengaturan") },
                        label = { Text("Gemini API") },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = NeonCyan,
                            selectedTextColor = NeonCyan,
                            unselectedIconColor = TextSecondary,
                            unselectedTextColor = TextSecondary
                        )
                    )
                }
            },
            containerColor = CyberBgDark
        ) { paddingValues ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues)
                    .background(CyberBgDark)
            ) {
                when (selectedTab.value) {
                    0 -> DashboardTab()
                    1 -> ComparisonTab()
                    2 -> SettingsTab()
                }

                // Modal Detail Analisis Komparatif Gemini
                selectedAppForDetail.value?.let { app ->
                    GeminiDetailDialog(app = app, onDismiss = { selectedAppForDetail.value = null })
                }
            }
        }
    }

    @Composable
    fun DashboardTab() {
        val threatCount = appList.count { it.localThreatLevel == ThreatLevel.MALWARE_CRITICAL }
        val suspiciousCount = appList.count { it.localThreatLevel == ThreatLevel.SUSPICIOUS }
        val safeCount = appList.count { it.localThreatLevel == ThreatLevel.SAFE || it.localThreatLevel == ThreatLevel.LOW_RISK }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Status Shield Card
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = CyberCardBg),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, CyberBorder)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    val statusColor = when {
                        threatCount > 0 -> NeonRed
                        suspiciousCount > 0 -> NeonYellow
                        appList.isNotEmpty() -> NeonGreen
                        else -> NeonCyan
                    }

                    Box(
                        modifier = Modifier
                            .size(90.dp)
                            .clip(CircleShape)
                            .background(statusColor.copy(alpha = 0.15f))
                            .border(2.dp, statusColor, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = when {
                                threatCount > 0 -> Icons.Default.Warning
                                suspiciousCount > 0 -> Icons.Default.HelpOutline
                                appList.isNotEmpty() -> Icons.Default.CheckCircle
                                else -> Icons.Default.Shield
                            },
                            contentDescription = null,
                            tint = statusColor,
                            modifier = Modifier.size(48.dp)
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Text(
                        text = when {
                            isScanning.value -> "SEDANG MEMINDAI SISTEM..."
                            threatCount > 0 -> "PERINGATAN: DITEMUKAN $threatCount ANCAMAN!"
                            suspiciousCount > 0 -> "$suspiciousCount APLIKASI MENCURIGAKAN"
                            appList.isNotEmpty() -> "PERANGKAT ANDA TERLINDUNGI"
                            else -> "SIAP MEMINDAI HP ANDA"
                        },
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        color = statusColor,
                        fontFamily = FontFamily.Monospace
                    )

                    Text(
                        text = "Mesin Heuristik Android + Analisis Pembanding Gemini AI",
                        fontSize = 12.sp,
                        color = TextSecondary,
                        textAlign = TextAlign.Center
                    )

                    if (isScanning.value) {
                        Spacer(modifier = Modifier.height(14.dp))
                        LinearProgressIndicator(
                            progress = scanProgress.value,
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(6.dp)
                                .clip(RoundedCornerShape(3.dp)),
                            color = NeonCyan,
                            trackColor = CyberBorder
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = currentScanningApp.value,
                            fontSize = 11.sp,
                            color = TextSecondary,
                            maxLines = 1
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Quick Stats Row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                StatCard(title = "Total Aplikasi", value = "${appList.size}", color = NeonCyan, modifier = Modifier.weight(1f))
                StatCard(title = "Bahaya", value = "$threatCount", color = NeonRed, modifier = Modifier.weight(1f))
                StatCard(title = "Mencurigakan", value = "$suspiciousCount", color = NeonYellow, modifier = Modifier.weight(1f))
                StatCard(title = "Aman", value = "$safeCount", color = NeonGreen, modifier = Modifier.weight(1f))
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Action Buttons
            Button(
                onClick = { startFullScan() },
                enabled = !isScanning.value,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
                colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
                shape = RoundedCornerShape(12.dp)
            ) {
                Icon(Icons.Default.Radar, contentDescription = null, tint = CyberBgDark)
                Spacer(modifier = Modifier.width(8.dp))
                Text("PINDAI SEMUA APLIKASI DI HP", color = CyberBgDark, fontWeight = FontWeight.Bold)
            }

            Spacer(modifier = Modifier.height(10.dp))

            OutlinedButton(
                onClick = { loadSimulatedThreatSandbox() },
                enabled = !isScanning.value,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                shape = RoundedCornerShape(12.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, NeonPurple)
            ) {
                Icon(Icons.Default.BugReport, contentDescription = null, tint = NeonPurple)
                Spacer(modifier = Modifier.width(8.dp))
                Text("MUAT SAMPEL UJI TROJAN (DEMO)", color = NeonPurple, fontWeight = FontWeight.SemiBold)
            }

            Spacer(modifier = Modifier.height(14.dp))

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = CyberCardBg.copy(alpha = 0.6f)),
                shape = RoundedCornerShape(12.dp)
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.AutoAwesome, contentDescription = null, tint = NeonPurple)
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = "Setiap aplikasi berisiko dapat langsung dikonsultasikan ke Gemini AI untuk mendapatkan second opinion dan rekomendasi mitigasi.",
                        fontSize = 11.sp,
                        color = TextSecondary
                    )
                }
            }
        }
    }

    @Composable
    fun ComparisonTab() {
        var filterIndex by remember { mutableStateOf(0) }
        val filteredList = remember(filterIndex, appList.size) {
            when (filterIndex) {
                1 -> appList.filter { it.localThreatLevel == ThreatLevel.MALWARE_CRITICAL || it.localThreatLevel == ThreatLevel.SUSPICIOUS }
                2 -> appList.filter { 
                    it.geminiAnalysis != null && (
                        it.comparisonStatus == ComparisonStatus.GEMINI_DETECTED_HIDDEN_THREAT || 
                        it.comparisonStatus == ComparisonStatus.LOCAL_FALSE_POSITIVE
                    )
                }
                3 -> appList.filter { it.localThreatLevel == ThreatLevel.SAFE }
                else -> appList
            }
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
        ) {
            Text(
                text = "KOMPARASI: MESIN LOKAL VS GEMINI AI",
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = TextPrimary,
                fontFamily = FontFamily.Monospace
            )
            Text(
                text = "Bandingkan hasil algoritma izin lokal dengan audit ancaman Gemini",
                fontSize = 11.sp,
                color = TextSecondary
            )

            Spacer(modifier = Modifier.height(10.dp))

            // Filter Chips
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                FilterChip(
                    selected = filterIndex == 0,
                    onClick = { filterIndex = 0 },
                    label = { Text("Semua (${appList.size})", fontSize = 11.sp) }
                )
                FilterChip(
                    selected = filterIndex == 1,
                    onClick = { filterIndex = 1 },
                    label = { Text("Ancaman", fontSize = 11.sp) }
                )
                FilterChip(
                    selected = filterIndex == 2,
                    onClick = { filterIndex = 2 },
                    label = { Text("Beda Pendapat", fontSize = 11.sp) }
                )
                FilterChip(
                    selected = filterIndex == 3,
                    onClick = { filterIndex = 3 },
                    label = { Text("Aman", fontSize = 11.sp) }
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            if (filteredList.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = if (appList.isEmpty()) "Belum ada pemindaian.\nTekan tombol Pindai di tab depan." else "Tidak ada aplikasi pada filter ini.",
                        color = TextSecondary,
                        textAlign = TextAlign.Center,
                        fontSize = 13.sp
                    )
                }
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(filteredList) { app ->
                        AppComparisonCard(app = app, onClick = { selectedAppForDetail.value = app })
                    }
                }
            }
        }
    }

    @Composable
    fun AppComparisonCard(app: AppSecurityProfile, onClick: () -> Unit) {
        val localColor = Color(app.localThreatLevel.colorHex)
        val geminiColor = if (app.geminiAnalysis != null) {
            Color(app.geminiAnalysis!!.verdict.colorHex)
        } else {
            TextMuted
        }

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onClick() },
            colors = CardDefaults.cardColors(containerColor = CyberCardBg),
            shape = RoundedCornerShape(12.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, if (app.localScore > 60) NeonRed.copy(alpha = 0.5f) else CyberBorder)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = app.appName,
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = TextPrimary
                        )
                        Text(
                            text = app.packageName,
                            fontSize = 11.sp,
                            color = TextSecondary,
                            maxLines = 1
                        )
                    }

                    // Score Badge
                    Surface(
                        color = localColor.copy(alpha = 0.2f),
                        shape = RoundedCornerShape(6.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, localColor)
                    ) {
                        Text(
                            text = "Risiko: ${app.localScore}%",
                            color = localColor,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))
                HorizontalDivider(color = CyberBorder, thickness = 0.8.dp)
                Spacer(modifier = Modifier.height(8.dp))

                // Dual-Engine Badges Side-by-Side
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Mesin Lokal
                    Column(modifier = Modifier.weight(1f)) {
                        Text("MESIN LOKAL", fontSize = 10.sp, color = TextSecondary, fontWeight = FontWeight.SemiBold)
                        Text(
                            text = app.localThreatLevel.label,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = localColor
                        )
                    }

                    // Pembanding Gemini AI
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.AutoAwesome, contentDescription = null, tint = NeonPurple, modifier = Modifier.size(12.dp))
                            Spacer(modifier = Modifier.width(3.dp))
                            Text("GEMINI AI", fontSize = 10.sp, color = NeonPurple, fontWeight = FontWeight.SemiBold)
                        }
                        if (app.geminiAnalysis != null) {
                            Text(
                                text = app.geminiAnalysis!!.verdict.label,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                color = geminiColor
                            )
                        } else if (app.isAnalyzingWithGemini) {
                            Text("Menganalisis...", fontSize = 11.sp, color = NeonCyan)
                        } else {
                            Text("Ketuk untuk Audit", fontSize = 11.sp, color = TextMuted)
                        }
                    }
                }
            }
        }
    }

    @Composable
    fun GeminiDetailDialog(app: AppSecurityProfile, onDismiss: () -> Unit) {
        val context = LocalContext.current
        var isAnalyzing by remember { mutableStateOf(false) }

        AlertDialog(
            onDismissRequest = onDismiss,
            containerColor = CyberSurfaceDark,
            title = {
                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.AutoAwesome, contentDescription = null, tint = NeonPurple)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Audit Perbandingan Gemini",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextPrimary
                        )
                    }
                    Text(text = app.appName, fontSize = 12.sp, color = NeonCyan)
                }
            },
            text = {
                LazyColumn(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    item {
                        Card(
                            colors = CardDefaults.cardColors(containerColor = CyberCardBg),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Column(modifier = Modifier.padding(10.dp)) {
                                Text("Penilaian Mesin Heuristik Lokal:", fontSize = 11.sp, color = TextSecondary)
                                Text("• Status: ${app.localThreatLevel.label} (Skor: ${app.localScore}/100)", fontWeight = FontWeight.Bold, color = Color(app.localThreatLevel.colorHex), fontSize = 12.sp)
                                if (app.localReasons.isNotEmpty()) {
                                    Text("• Alasan: ${app.localReasons.joinToString("\n• ")}", fontSize = 11.sp, color = TextPrimary)
                                }
                            }
                        }
                    }

                    item {
                        val gemini = app.geminiAnalysis
                        if (gemini != null) {
                            Card(
                                colors = CardDefaults.cardColors(containerColor = CyberCardBg),
                                shape = RoundedCornerShape(8.dp),
                                border = androidx.compose.foundation.BorderStroke(1.dp, NeonPurple)
                            ) {
                                Column(modifier = Modifier.padding(10.dp)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(Icons.Default.SmartToy, contentDescription = null, tint = NeonPurple, modifier = Modifier.size(16.dp))
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text("Hasil Analisis Gemini AI:", fontWeight = FontWeight.Bold, color = NeonPurple, fontSize = 13.sp)
                                    }
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text("• Kategori: ${gemini.threatFamily}", fontWeight = FontWeight.Bold, color = TextPrimary, fontSize = 12.sp)
                                    Text("• Tingkat Ancaman: ${gemini.verdict.label} (${gemini.threatScore}%)", color = Color(gemini.verdict.colorHex), fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Text("Analisis Mendalam AI:", fontSize = 11.sp, color = TextSecondary, fontWeight = FontWeight.SemiBold)
                                    Text(gemini.aiAnalysisDetail, fontSize = 12.sp, color = TextPrimary)
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Text("Rekomendasi Tindakan: ${gemini.actionRecommendation}", color = NeonCyan, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                                    Text("Saran: ${gemini.securityAdvice}", color = TextSecondary, fontSize = 11.sp)
                                }
                            }
                        } else {
                            Button(
                                onClick = {
                                    isAnalyzing = true
                                    lifecycleScope.launch {
                                        app.geminiAnalysis = geminiEngine.auditAppWithGemini(app)
                                        isAnalyzing = false
                                        // Force UI refresh
                                        val idx = appList.indexOf(app)
                                        if (idx != -1) {
                                            appList[idx] = app.copy(geminiAnalysis = app.geminiAnalysis)
                                            selectedAppForDetail.value = appList[idx]
                                        }
                                    }
                                },
                                enabled = !isAnalyzing,
                                modifier = Modifier.fillMaxWidth(),
                                colors = ButtonDefaults.buttonColors(containerColor = NeonPurple)
                            ) {
                                if (isAnalyzing) {
                                    CircularProgressIndicator(modifier = Modifier.size(16.dp), color = Color.White)
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Gemini Sedang Mengaudit...", fontSize = 12.sp)
                                } else {
                                    Icon(Icons.Default.AutoAwesome, contentDescription = null)
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Minta Analisis Pembanding Gemini AI", fontSize = 12.sp)
                                }
                            }
                        }
                    }

                    // Izin yang diminta
                    item {
                        Text("Izin Berbahaya Diminta (${app.dangerousPermissions.size}):", fontSize = 11.sp, color = TextSecondary)
                        app.dangerousPermissions.forEach { perm ->
                            Text("• ${perm.substringAfterLast(".")}", fontSize = 10.sp, color = NeonYellow)
                        }
                    }
                }
            },
            confirmButton = {
                if (app.localScore > 50 || (app.geminiAnalysis?.threatScore ?: 0) > 50) {
                    Button(
                        onClick = {
                            val uninstallIntent = Intent(Intent.ACTION_DELETE).apply {
                                data = Uri.parse("package:${app.packageName}")
                            }
                            context.startActivity(uninstallIntent)
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = NeonRed)
                    ) {
                        Icon(Icons.Default.Delete, contentDescription = null, tint = Color.White)
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Copot / Hapus Aplikasi", color = Color.White)
                    }
                } else {
                    TextButton(onClick = onDismiss) {
                        Text("Tutup", color = NeonCyan)
                    }
                }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) {
                    Text("Tutup", color = TextSecondary)
                }
            }
        )
    }

    @Composable
    fun SettingsTab() {
        var apiKeyText by remember { mutableStateOf(geminiEngine.getApiKey()) }
        var selectedModel by remember { mutableStateOf(geminiEngine.getModelName()) }
        val context = LocalContext.current

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = "PENGATURAN GOOGLE GEMINI AI",
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = TextPrimary,
                fontFamily = FontFamily.Monospace
            )
            Text(
                text = "Konfigurasikan API Key Gemini agar antivirus dapat membandingkan ancaman secara real-time langsung ke server Google AI.",
                fontSize = 12.sp,
                color = TextSecondary
            )

            Card(
                colors = CardDefaults.cardColors(containerColor = CyberCardBg),
                shape = RoundedCornerShape(12.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, CyberBorder)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("Google Gemini API Key:", fontSize = 12.sp, color = NeonCyan, fontWeight = FontWeight.Bold)
                    Spacer(modifier = Modifier.height(6.dp))
                    OutlinedTextField(
                        value = apiKeyText,
                        onValueChange = { apiKeyText = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("Contoh: AIzaSy...", color = TextMuted) },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = NeonCyan,
                            unfocusedBorderColor = CyberBorder,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        )
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Tips: Dapatkan API Key gratis di Google AI Studio (aistudio.google.com). Jika dikosongkan, antivirus akan menggunakan mode Simulasi Cerdas bawaan.",
                        fontSize = 11.sp,
                        color = TextMuted
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Button(
                        onClick = {
                            geminiEngine.saveApiKey(apiKeyText)
                            Toast.makeText(context, "API Key Gemini Berhasil Disimpan!", Toast.LENGTH_SHORT).show()
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.Save, contentDescription = null, tint = CyberBgDark)
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Simpan Konfigurasi", color = CyberBgDark, fontWeight = FontWeight.Bold)
                    }
                }
            }

            Card(
                colors = CardDefaults.cardColors(containerColor = CyberCardBg),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("Pilih Model Gemini:", fontSize = 12.sp, color = NeonCyan, fontWeight = FontWeight.Bold)
                    Spacer(modifier = Modifier.height(8.dp))
                    listOf("gemini-1.5-flash", "gemini-2.0-flash", "gemini-1.5-pro").forEach { model ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    selectedModel = model
                                    geminiEngine.setModelName(model)
                                }
                                .padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = selectedModel == model,
                                onClick = {
                                    selectedModel = model
                                    geminiEngine.setModelName(model)
                                },
                                colors = RadioButtonDefaults.colors(selectedColor = NeonCyan)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Column {
                                Text(model, color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                                Text(
                                    if (model.contains("flash")) "Cepat & Efisien untuk pemindaian instan" else "Analisis heuristik paling akurat dan mendalam",
                                    color = TextSecondary,
                                    fontSize = 11.sp
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    @Composable
    fun StatCard(title: String, value: String, color: Color, modifier: Modifier = Modifier) {
        Card(
            modifier = modifier,
            colors = CardDefaults.cardColors(containerColor = CyberCardBg),
            shape = RoundedCornerShape(10.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, color.copy(alpha = 0.4f))
        ) {
            Column(
                modifier = Modifier.padding(10.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(text = value, fontSize = 18.sp, fontWeight = FontWeight.Bold, color = color)
                Text(text = title, fontSize = 9.sp, color = TextSecondary, textAlign = TextAlign.Center)
            }
        }
    }

    private fun startFullScan() {
        if (isScanning.value) return
        isScanning.value = true
        scanProgress.value = 0f
        appList.clear()

        lifecycleScope.launch {
            val installed = localEngine.scanAllInstalledApps(includeSystemApps = false)
            val total = installed.size.coerceAtLeast(1)

            for ((index, app) in installed.withIndex()) {
                currentScanningApp.value = "Memeriksa: ${app.appName}"
                scanProgress.value = (index + 1).toFloat() / total
                appList.add(app)
                kotlinx.coroutines.delay(40) // Efek visual scanner
            }

            // Secara otomatis minta audit Gemini untuk aplikasi yang dinilai mencurigakan/bahaya oleh mesin lokal
            val highRiskApps = appList.filter { it.localThreatLevel == ThreatLevel.MALWARE_CRITICAL || it.localThreatLevel == ThreatLevel.SUSPICIOUS }
            for (riskyApp in highRiskApps) {
                currentScanningApp.value = "Membandingkan dengan Gemini AI: ${riskyApp.appName}"
                val geminiVerdict = geminiEngine.auditAppWithGemini(riskyApp)
                val idx = appList.indexOf(riskyApp)
                if (idx != -1) {
                    appList[idx] = riskyApp.copy(geminiAnalysis = geminiVerdict)
                }
            }

            isScanning.value = false
            currentScanningApp.value = "Pemindaian selesai!"
            Toast.makeText(this@MainActivity, "Pemindaian Selesai! ${installed.size} aplikasi diperiksa.", Toast.LENGTH_SHORT).show()
        }
    }

    private fun loadSimulatedThreatSandbox() {
        appList.clear()
        
        // Sampel 1: Pola Trojan Perbankan Indonesia Populer (Surat Undangan APK)
        val sample1 = AppSecurityProfile(
            appName = "Surat_Undangan_Pernikahan.apk",
            packageName = "com.undangan.digital.pernikahan",
            versionName = "1.0.3",
            isSystemApp = false,
            apkPath = "/storage/emulated/0/Download/Surat_Undangan_Pernikahan.apk",
            fileSizeMb = 3.45,
            sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            requestedPermissions = listOf(
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.RECEIVE_BOOT_COMPLETED"
            ),
            dangerousPermissions = listOf(
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.BIND_ACCESSIBILITY_SERVICE"
            ),
            hasAccessibilityAbuse = true,
            hasOverlayPermission = true,
            hasSmsIntercept = true,
            localThreatLevel = ThreatLevel.MALWARE_CRITICAL,
            localScore = 95,
            localReasons = listOf(
                "WASPADA: Nama aplikasi berkedok dokumen/undangan namun meminta izin membaca SMS & Layanan Aksesibilitas",
                "Kombinasi Overlay (tampilan tiruan) + Penyadapan SMS + Aksesibilitas untuk mencuri kode OTP perbankan",
                "Meminta izin otomatis aktif saat HP dinyalakan (Boot Completed)"
            ),
            geminiAnalysis = GeminiAnalysis(
                verdict = ThreatLevel.MALWARE_CRITICAL,
                threatScore = 99,
                threatFamily = "Indonesian Banking Trojan (SMS Sniffer / Overlay Dropper)",
                aiAnalysisDetail = "Gemini AI menyetujui Mesin Lokal: 100% konsensus MALWARE. Ini adalah modus penipuan berkedok Surat Undangan APK yang menyadap SMS OTP m-Banking dan menggunakan Layanan Aksesibilitas untuk menguras rekening korban.",
                suspiciousFactors = listOf(
                    "Aplikasi dokumen tidak membutuhkan izin SMS sama sekali",
                    "Aksesibilitas digunakan untuk melakukan auto-click transfer dana tanpa interaksi pengguna",
                    "Overlay digunakan untuk menutupi layar dengan antarmuka palsu"
                ),
                actionRecommendation = "HAPUS SEGERA & BLOKIR NOMOR PENGIRIM",
                securityAdvice = "Jangan pernah membuka file .apk berkedok undangan, resi paket, surat tilang, atau tagihan PLN yang dikirimkan lewat WhatsApp.",
                modelUsed = "gemini-1.5-flash"
            )
        )

        // Sampel 2: Adware / Silent Clicker
        val sample2 = AppSecurityProfile(
            appName = "Super Fast Cleaner Pro",
            packageName = "com.tools.battery.cleaner.booster",
            versionName = "2.1.0",
            isSystemApp = false,
            apkPath = "/data/app/com.tools.battery.cleaner.booster/base.apk",
            fileSizeMb = 18.2,
            sha256 = "c2e42a98f123bc456d9876543210fedcba9876543210fedcba9876543210fedc",
            requestedPermissions = listOf(
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.ACCESS_BACKGROUND_LOCATION",
                "android.permission.PACKAGE_USAGE_STATS",
                "android.permission.WAKE_LOCK"
            ),
            dangerousPermissions = listOf(
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.ACCESS_BACKGROUND_LOCATION"
            ),
            hasOverlayPermission = true,
            localThreatLevel = ThreatLevel.SUSPICIOUS,
            localScore = 55,
            localReasons = listOf(
                "Meminta izin menampilkan jendela di atas aplikasi lain (Overlay)",
                "Mengakses lokasi perangkat di latar belakang tanpa alasan fungsional yang jelas"
            ),
            geminiAnalysis = GeminiAnalysis(
                verdict = ThreatLevel.SUSPICIOUS,
                threatScore = 60,
                threatFamily = "Adware / Aggressive Telemetry PUA",
                aiAnalysisDetail = "Gemini AI mengidentifikasi bahwa aplikasi utilitas pembersih RAM ini mengandung modul monetisasi agresif dan analitik pelacakan lokasi pengguna yang tidak wajar untuk alat 'cleaner'.",
                suspiciousFactors = listOf(
                    "Pelacakan lokasi latar belakang untuk profiling iklan berbayar",
                    "Izin overlay sering disalahgunakan memunculkan iklan pop-up di layar utama"
                ),
                actionRecommendation = "BATASI IZIN ATAU GANTI DENGAN FITUR BAWAAN HP",
                securityAdvice = "Sebagian besar aplikasi cleaner pihak ketiga tidak efektif dan hanya menguras baterai.",
                modelUsed = "gemini-1.5-flash"
            )
        )

        // Sampel 3: Aplikasi Bersih Normal (Kalkulator Sah)
        val sample3 = AppSecurityProfile(
            appName = "Kalkulator Cerdas Ilmiah",
            packageName = "com.math.calculator.scientific",
            versionName = "3.4.0",
            isSystemApp = false,
            apkPath = "/data/app/com.math.calculator.scientific/base.apk",
            fileSizeMb = 5.6,
            sha256 = "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
            requestedPermissions = listOf(
                "android.permission.VIBRATE"
            ),
            dangerousPermissions = emptyList(),
            localThreatLevel = ThreatLevel.SAFE,
            localScore = 0,
            localReasons = listOf("Tidak meminta izin berbahaya apapun."),
            geminiAnalysis = GeminiAnalysis(
                verdict = ThreatLevel.SAFE,
                threatScore = 0,
                threatFamily = "Aplikasi Bersih Terpercaya",
                aiAnalysisDetail = "Gemini AI memverifikasi: Konsensus AMAN. Hanya meminta izin getar (haptic feedback) saat tombol ditekan. Nol indikasi kode berbahaya.",
                suspiciousFactors = emptyList(),
                actionRecommendation = "AMAN DIGUNAKAN",
                securityAdvice = "Aplikasi ini mematuhi standar privasi Android.",
                modelUsed = "gemini-1.5-flash"
            )
        )

        // Sampel 4: Uji Standar Virus Dunia (EICAR Test)
        val sample4 = AppSecurityProfile(
            appName = "EICAR Standard Antivirus Test File",
            packageName = "org.eicar.test.standard",
            versionName = "1.0",
            isSystemApp = false,
            apkPath = "/storage/emulated/0/Download/eicar_test.apk",
            fileSizeMb = 0.01,
            sha256 = MalwareDatabase.EICAR_SHA256,
            requestedPermissions = emptyList(),
            dangerousPermissions = emptyList(),
            localThreatLevel = ThreatLevel.MALWARE_CRITICAL,
            localScore = 100,
            localReasons = listOf("TERDETEKSI: Sampel Virus Standar Uji EICAR"),
            geminiAnalysis = GeminiAnalysis(
                verdict = ThreatLevel.MALWARE_CRITICAL,
                threatScore = 100,
                threatFamily = "Antivirus Test Signature (EICAR)",
                aiAnalysisDetail = "Gemini AI mengonfirmasi: Berkas ini memiliki hash identik dengan berkas uji EICAR resmi yang digunakan oleh seluruh industri antivirus dunia untuk memvalidasi efektivitas deteksi.",
                suspiciousFactors = listOf("Signature Hash EICAR terverifikasi"),
                actionRecommendation = "HAPUS (BERKAS UJI BERHASIL DIIDENTIFIKASI)",
                securityAdvice = "Ini adalah berkas uji coba aman tanpa muatan berbahaya nyata.",
                modelUsed = "gemini-1.5-flash"
            )
        )

        appList.addAll(listOf(sample1, sample2, sample3, sample4))
        Toast.makeText(this, "4 Sampel Uji Dimuat (Termasuk Trojan Undangan & EICAR)!", Toast.LENGTH_SHORT).show()
        selectedTab.value = 1 // Langsung buka tab komparasi agar pengguna melihat perbedaannya
    }
}
