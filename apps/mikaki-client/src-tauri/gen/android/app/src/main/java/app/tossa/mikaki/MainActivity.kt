package app.tossa.mikaki

import android.os.Bundle
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import androidx.core.view.WindowCompat
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature

class MainActivity : TauriActivity() {
  private var darkAppearance: Boolean? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }

  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
      // Only the bundled top-level UI can change icon contrast. No key or session access.
      WebViewCompat.addWebMessageListener(
        webView, "MikakiSystemBars",
        setOf("https://tauri.localhost", "http://tauri.localhost")
      ) { _, message, _, isMainFrame, _ ->
        if (isMainFrame && message.data in setOf("light", "dark")) {
          darkAppearance = message.data == "dark"
          updateSystemBars()
        }
      }
    }
  }

  override fun onWindowFocusChanged(hasFocus: Boolean) {
    super.onWindowFocusChanged(hasFocus)
    if (hasFocus) updateSystemBars()
  }

  private fun updateSystemBars() {
    val dark = darkAppearance ?: return
    WindowCompat.getInsetsController(window, window.decorView).apply {
      isAppearanceLightStatusBars = !dark
      isAppearanceLightNavigationBars = !dark
    }
  }
}
