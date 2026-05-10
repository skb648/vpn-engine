package com.vpnengine.nativecore

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vpnengine.nativecore.ui.screen.VpnScreen
import com.vpnengine.nativecore.ui.theme.VpnTheme

/**
 * MainActivity — Entry point for the ZeroTier P2P Mesh VPN app.
 *
 * Android 16+ Compatibility:
 *   - VPN permission via ActivityResultContracts
 *   - Global exception handler prevents crashes
 *   - No deprecated APIs used
 */
class MainActivity : ComponentActivity() {

    companion object {
        private const val TAG = "MainActivity"
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val viewModel = lastViewModelRef
        if (viewModel != null) {
            val granted = result.resultCode == RESULT_OK
            viewModel.onVpnPermissionResult(granted)
        }
    }

    // Temporary reference to ViewModel for permission callback
    @Volatile
    private var lastViewModelRef: VpnViewModel? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Global exception handler — prevents force-close
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            Log.e(TAG, "Uncaught exception on ${thread.name}", throwable)
            // Reset VPN state so the UI shows an error instead of being stuck
            VpnStateHolder.updateState(
                VpnState.Error("Unexpected error: ${throwable.localizedMessage ?: throwable.javaClass.simpleName}")
            )
            // Try to stop the engine if it's running
            try { ZtEngine.stopSafe() } catch (_: Exception) {}
        }

        setContent {
            VpnTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = Color(0xFF0A0E1A)
                ) {
                    val viewModel: VpnViewModel = viewModel()

                    // Store ref for permission callback
                    LaunchedEffect(viewModel) {
                        lastViewModelRef = viewModel
                    }

                    VpnScreen(
                        viewModel = viewModel,
                        onPermissionRequest = { intent ->
                            vpnPermissionLauncher.launch(intent)
                        }
                    )
                }
            }
        }
    }
}
