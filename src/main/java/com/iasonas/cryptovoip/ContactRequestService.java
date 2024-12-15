package com.iasonas.cryptovoip;

/*
This classs is used to handle request from AddRemoteContact Activity
 */

import android.app.Activity;
import android.app.IntentService;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.os.Environment;
import android.os.ResultReceiver;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class ContactRequestService extends IntentService {

    String mode;
    String result;
    String globalresult;

    public ContactRequestService() {
        super("test-service");
    }

    @Override
    protected void onHandleIntent(Intent intent) {

        ResultReceiver  rec = intent.getParcelableExtra("listener");
        mode = intent.getStringExtra("mode");


        if(mode.equals("Normal") || mode.equals("Normal1")) {

            String name = intent.getStringExtra("Name");
            byte[] key = intent.getByteArrayExtra("Ckey");
            //result="ok";
            result = addToKeyStore(name, key);
        } else if(mode.equals("CR")) {

            String fromAlias = intent.getStringExtra("fromAlias");
            String CIP = intent.getStringExtra("IP");

            byte[] keyCR = getMessageCR(CIP);
            result = addToKeyStore(fromAlias, keyCR);

        } else if(mode.equals("HP")) {

            String fromAlias = intent.getStringExtra("fromAlias");
            String myName = intent.getStringExtra("myName");
            String UEpoint1 = intent.getStringExtra("endpoint1");
            String UEpoint2 = intent.getStringExtra("endpoint2");
            String serverIP = getIP("server");
            String response = "HP:RESPONSE:" + myName + ":" + fromAlias + ":" + "ADDREMOTECONTACT";
            UdpEndpoints endpoints = sendresponseHP(response, serverIP);

            endpoints.setUDP1(UEpoint1);
            endpoints.setUDP2(UEpoint2);

            initHP(endpoints);
            byte[] keyHP = receivemessageHP(endpoints);
            result = addToKeyStore(fromAlias, keyHP);

        }

        // To send a message to the Activity, create a pass a Bundle
        Bundle bundle = new Bundle();
        bundle.putString("result", result);
        // Here we call send passing a resultCode and the bundle of extras
        rec.send(Activity.RESULT_OK, bundle);
    }

    //This method is used to receive the encoded certificate from the peer if mode is HP

    public byte[] receivemessageHP(UdpEndpoints UE) {

        byte [] key;
        key = "Hello".getBytes();

        try {

            UE.getSock1().setSoTimeout(500);

            byte[] ACKbuf = "NOACK".getBytes();
            DatagramPacket ACKPacket = new DatagramPacket(ACKbuf, ACKbuf.length);

            String addr1[] = UE.getUDP1().split(":");
            InetAddress destination = InetAddress.getByName(addr1[0]);
            int port = Integer.getInteger(addr1[1]);
            byte[] ACKbuf2 = "NOACK".getBytes();

            DatagramPacket ACK2Packet = new DatagramPacket(ACKbuf2, ACKbuf2.length, destination, port);

            DatagramPacket certPacket = new DatagramPacket(key, key.length, destination, port);

            while(Arrays.toString(key).equals("Hello")) {

                UE.getSock1().receive(certPacket);
            }

            int j=0;
            while(Arrays.toString(ACKbuf2).equals("NOACK") && j<5 ) {

                UE.getSock1().send(ACKPacket);
                UE.getSock1().receive(ACK2Packet);
                j++;
            }

            UE.getSock1().setSoTimeout(0);

            return key;

        }catch(java.io.IOException e) { globalresult = "receivemessageHP IO Exception"; }

        return key;
    }


//This method is used to send the ersponse HP message to the server and create the udp sockets with the rendeuzvous server

    public UdpEndpoints sendresponseHP(String toSend, String SerIp) {

        UdpEndpoints endp = new UdpEndpoints();

        try {

            PrintStream out;
            BufferedReader in;
            Socket socket = new Socket();
            InetSocketAddress socketaddr = new InetSocketAddress(SerIp, 9999);
            while(!socket.isConnected()) {
                socket.connect(socketaddr, 0);
            }
            out = new PrintStream(socket.getOutputStream());
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            ///////////////////////////////////////////////////////////////////////////

            out.println(toSend);
            String line = in.readLine();
            String lineinfo[] = line.split(":");
            InetAddress destination = InetAddress.getByName(lineinfo[0]);
            int port1 = Integer.getInteger(lineinfo[1]);

            byte[] ACKbuffer = "NOACK".getBytes();
            DatagramPacket ACKPacket = new DatagramPacket(ACKbuffer, ACKbuffer.length);

            byte[]  helloBuffer = "Hello".getBytes();
            DatagramSocket Dsock1 = new DatagramSocket();
            Dsock1.setSoTimeout(1000);
            Dsock1.setReuseAddress(true);
            DatagramPacket HelloPacket = new DatagramPacket(helloBuffer, helloBuffer.length, destination, port1 );

            while(Arrays.toString(ACKbuffer).equals("NOACK")) {

                Dsock1.send(HelloPacket);
                Dsock1.receive(ACKPacket);
            }

            ACKbuffer = "NOACK".getBytes();

            String line2 = in.readLine();
            String lineinfo2[] = line2.split(":");
            InetAddress destination2 = InetAddress.getByName(lineinfo2[0]);
            int port2 = Integer.getInteger(lineinfo2[1]);

            byte[]  helloBuffer2 = "Hello".getBytes();
            DatagramSocket Dsock2 = new DatagramSocket();
            Dsock2.setSoTimeout(1000);
            Dsock2.setReuseAddress(true);
            DatagramPacket HelloPacket2 = new DatagramPacket(helloBuffer2, helloBuffer2.length, destination2, port2 );

            while(Arrays.toString(ACKbuffer).equals("NOACK")) {

                Dsock2.send(HelloPacket2);
                Dsock2.receive(ACKPacket);
            }

            Dsock1.setSoTimeout(0);
            Dsock2.setSoTimeout(0);


            in.close();
            out.close();
            socket.close();

            endp.setSock1(Dsock1);
            endp.setSock2(Dsock2);

            return endp;

        }catch(java.io.IOException e) { globalresult = "sendresponseHP IO exception"; }

        return endp;
    }

    //This method is used to send packets at the endpoints of the peer from the pre existing Udp sessions
    // with the rendeuzvous server

    public void initHP(UdpEndpoints udpep) {

        try {

            String lineinfo[] = udpep.getUDP1().split(":");
            InetAddress destination = InetAddress.getByName(lineinfo[0]);
            int port1 = Integer.getInteger(lineinfo[1]);

            byte[] helloBuffer = "Hello".getBytes();
            DatagramPacket HelloPacket = new DatagramPacket(helloBuffer, helloBuffer.length, destination, port1);
            udpep.getSock1().send(HelloPacket);

            String lineinfo2[] = udpep.getUDP2().split(":");
            InetAddress destination2 = InetAddress.getByName(lineinfo2[0]);
            int port2 = Integer.getInteger(lineinfo2[1]);

            byte[] helloBuffer2 = "Hello".getBytes();
            DatagramPacket HelloPacket2 = new DatagramPacket(helloBuffer2, helloBuffer2.length, destination2, port2);
            udpep.getSock2().send(HelloPacket2);


        } catch(java.io.IOException e) { globalresult = "intiHP IO exception"; }
    }

    //This method is used to retrive the IP from the SQLite DB

    public String getIP(String name) {

        String IPAddress;
        SQLiteDatabase mydb;
        Cursor resultset;

        mydb = openOrCreateDatabase("mydata.db", Context.MODE_PRIVATE, null);
        resultset = mydb.rawQuery("SELECT IP FROM IPTable WHERE name = ?", new String[] { name });
        resultset.moveToFirst();
        IPAddress = resultset.getString(1);
        mydb.close();
        resultset.close();

        return IPAddress;


    }

    //This method is used to receive the encoded certificate from the peer if mode is CR

    public byte[] getMessageCR(String cIP) {

        byte[] key = null;

        try {

            InputStream inStream;

            if (mode.equals("CR")) {
                Socket socket = new Socket();
                InetSocketAddress socketaddr = new InetSocketAddress(cIP, 2222);
                while (!socket.isConnected()) {
                    socket.connect(socketaddr, 0);
                }

                inStream = socket.getInputStream();
                int result = inStream.read(key);

                inStream.close();
                socket.close();
            }


        }catch(java.io.IOException e) { globalresult = "getmessageCR IO Exception"; }

        return key;
    }

    //This method is used to create an entry in the keystore to save the received key and the alias

    public String addToKeyStore(String Cname, byte[] ckey) {

        try {

            File remoteCert = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES), "cert1.12");
            boolean result = remoteCert.createNewFile();
            // if(result) {return "FILE_CREATED"; }

            FileOutputStream os = new FileOutputStream(remoteCert);
            os.write(ckey);
            os.close();

            File file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES), "1.p12");
            KeyStore keyStore = KeyStore.getInstance("PKCS12");


            FileInputStream instreamKS = new FileInputStream(file);
            keyStore.load(instreamKS, "password".toCharArray());
            instreamKS.close();

            //if(keyStore.containsAlias(Cname)) {  return "ADDTOKEYSTORE_EXISTS";   }

            File certfile = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES), "cert1.12");
            if(!certfile.exists()) { return "ADDTOKEYSTORE_CERT_FILE_NP"; }
            InputStream inStream = new FileInputStream(certfile);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);
            keyStore.setCertificateEntry(Cname, cert);
            inStream.close();

            certfile.delete();
            //if(keyStore.containsAlias(Cname)) {  return "ADDED_SUCCESS";   }

            KeyStore.ProtectionParameter protparam = new KeyStore.PasswordProtection("password".toCharArray());
            KeyStore.PrivateKeyEntry mycert = (KeyStore.PrivateKeyEntry) keyStore.getEntry("me", protparam);

            X509Certificate Cert = (X509Certificate) mycert.getCertificate();

            if(cert.equals(Cert)) { return "MATCH"; }

            OutputStream outStream = new FileOutputStream(file);
            keyStore.store(outStream, "password".toCharArray());




        } catch(java.io.IOException e) { return "ADDTOKEYSTORE_IO_EXCEPTION"; }
        catch(java.security.NoSuchAlgorithmException e) { return "ADDTOKEYSTORE_NSALGO_EXCEPTION"; }
        catch(java.security.cert.CertificateException e) { return "ADDTOKEYSTORE_CERT_EXCEPTION"; }
        catch(java.security.KeyStoreException e) { return "ADDTOKEYSTORE_KEYSTORE_EXCEPTION";  }
        catch(java.security.UnrecoverableEntryException e) { return "ADDTOKEYSTORE_UEE"; }


        return "SUCCESS";
    }

}

