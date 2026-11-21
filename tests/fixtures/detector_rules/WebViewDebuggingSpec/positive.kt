package fixture

import android.webkit.WebView

class Screen(private val webView: WebView) {
    fun setupWebView() {
        WebView.setWebContentsDebuggingEnabled(true)
        webView.settings.javaScriptEnabled = true
    }
}
