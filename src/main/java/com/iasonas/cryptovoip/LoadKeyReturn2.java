package com.iasonas.cryptovoip;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class LoadKeyReturn2 {

    PrivateKey PrivateKey = null;
    X509Certificate peerCert = null;
    String result;


    public void setPrivate(PrivateKey one) { PrivateKey = one; }
    public PrivateKey getPrivate() { return PrivateKey; }

    public void setPublic(X509Certificate one) { peerCert = one; }
    public X509Certificate getPublic() { return peerCert; }

    public void setResult(String one) { result = one; }
    public String getResult() { return result; }

}
