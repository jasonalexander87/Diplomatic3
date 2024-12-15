package com.iasonas.cryptovoip;

/*
this class actually performs the alias/cert instertion into the preexisting keystore */

import android.app.Activity;
import android.app.IntentService;
import android.content.Intent;
import android.os.Bundle;
import android.os.Environment;
import android.os.ResultReceiver;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class AddContactService extends IntentService {

    public AddContactService() {
        super("test-service");
    }

    @Override
    protected void onHandleIntent(Intent intent) {

        ResultReceiver rec = intent.getParcelableExtra("receiver");

        String alias = intent.getStringExtra("alias");

        String result = addContact(alias);
        Bundle bundle = new Bundle();
        bundle.putString("result", result);

        rec.send(Activity.RESULT_OK, bundle);
    }

    //This method opens the keystore reads the certificate from file and saves it into keystore

    public String addContact(String Cname) {

        try {

            File file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES), "keystore.p12");
            KeyStore keyStore = KeyStore.getInstance("PKCS12");


            FileInputStream instreamKS = new FileInputStream(file);
            keyStore.load(instreamKS, "password".toCharArray());
            instreamKS.close();

            if(keyStore.containsAlias(Cname)) {  return "alias already exists";   }

            File certfile = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES), "mycert");
            if(!certfile.exists()) { return "please place the contact cert"; }
            InputStream inStream = new FileInputStream(certfile);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);
            keyStore.setCertificateEntry(Cname, cert);
            inStream.close();

            OutputStream outStream = new FileOutputStream(file);
            keyStore.store(outStream, "password".toCharArray());

        } catch(java.io.IOException e) { return "Exception IO";  }
        catch(java.security.NoSuchAlgorithmException e) { return "exception nosuchAlgo"; }
        catch(java.security.cert.CertificateException e) { return "exception cert"; }
        catch(java.security.KeyStoreException e) { return "exception keystore";  }


        return "success";
    }

}

