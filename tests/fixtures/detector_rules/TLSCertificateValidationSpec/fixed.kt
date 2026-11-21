package fixture

import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager
import okhttp3.OkHttpClient

class Clients(private val pinned: X509TrustManager) {
    fun lanClient(): OkHttpClient {
        val checking = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                pinned.checkClientTrusted(chain, authType)
            }
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                if (chain.isNullOrEmpty()) throw CertificateException("empty chain")
                pinned.checkServerTrusted(chain, authType)
            }
            override fun getAcceptedIssuers(): Array<X509Certificate> = pinned.acceptedIssuers
        }
        return OkHttpClient.Builder().build()
    }
}
