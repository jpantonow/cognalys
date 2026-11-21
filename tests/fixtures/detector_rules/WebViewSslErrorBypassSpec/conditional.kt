package fixture

import android.net.http.SslError
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient

fun configure(webView: WebView, pinned: (SslError) -> Boolean) {
    webView.webViewClient = object : WebViewClient() {
        override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
            if (pinned(error)) {
                handler.proceed()
            } else {
                handler.cancel()
            }
        }
    }
}
