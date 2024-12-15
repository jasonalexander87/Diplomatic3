package com.iasonas.cryptovoip;

/*
This class is used to save two keys
 */

import java.security.PrivateKey;
import java.security.PublicKey;

public class LoadKeyReturn {

    PrivateKey PrivateKey = null;
    PublicKey PublicKey = null;
    String result;


    public void setPrivate(PrivateKey one) { PrivateKey = one; }
    public PrivateKey getPrivate() { return PrivateKey; }

    public void setPublic(PublicKey one) { PublicKey = one; }
    public PublicKey getPublic() { return PublicKey; }

    public void setResult(String one) { result = one; }
    public String getResult() { return result; }

}