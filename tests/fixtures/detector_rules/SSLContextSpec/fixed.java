package fixture;

import javax.net.ssl.SSLContext;

class Tls {
    SSLContext context() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(null, null, null);
        return context;
    }
}
