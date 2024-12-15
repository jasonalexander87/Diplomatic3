package com.iasonas.cryptovoip;

/*
This class is used to return the result from The handshake proccess
 */

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class HandshakeResult {

    public SecretKeySpec key;
    public IvParameterSpec InitVector;
    public String result;

    public void setstatus(String one) { result = one; }
    public String getstatus() { return result; }

    public void setKey(SecretKeySpec one) { key = one; }
    public SecretKeySpec getKey() { return key; }

    public void setIV( IvParameterSpec two) { InitVector = two; }
    public IvParameterSpec getIV() { return InitVector; }

}