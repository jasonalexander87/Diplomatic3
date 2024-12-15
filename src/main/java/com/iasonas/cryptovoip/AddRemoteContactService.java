package com.iasonas.cryptovoip;

import android.app.Activity;
import android.app.IntentService;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.os.Environment;
import android.os.ResultReceiver;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 *Thia class is used to perform the friend request its sends the encoded cert of the user to the selected peer
 */

public class AddRemoteContactService extends IntentService {

    String UDPendpoint1;
    String UDPendpoint2;
    boolean responseflag;
    DatagramSocket Dsock1;
    DatagramSocket Dsock2;

    String globalresult;
    String ContactName;
    String myName;
    String result;
    String myIP;
    String cIP;
    String serverIP;
    byte[] cert;
    String request;
    String mode;



    public AddRemoteContactService() {
        super("test-service");
    }

    @Override
    protected void onHandleIntent(Intent intent) {
        ResultReceiver  rec = intent.getParcelableExtra("listener");

        LocalBroadcastManager localBroadcastManager = LocalBroadcastManager.getInstance(this);
        BroadcastReceiver br = new MyBroadcastReceiverARC();
        IntentFilter filter = new IntentFilter();
        filter.addAction("com.iasonas.cryptovoip.HPRESPONSEARC");
        localBroadcastManager.registerReceiver(br, filter);

        myName = intent.getStringExtra("Myname");
        ContactName = intent.getStringExtra("Cname");

        myIP = getIP(myName);
        cIP = getIP(ContactName);


        if(myIP.equals("0.0.0.0")&cIP.equals("0.0.0.0")) {
            mode = "HP";
        } else if(cIP.equals("0.0.0.0")) {
            mode = "CR";
        } else if(myIP.equals("0.0.0.0")) {
            mode = "Normal1";
        }
        else { mode = "Normal"; }

        if(mode.equals("Normal") || mode.equals("Normal1")) {
            result = sendrequest(myName, cIP);


        }

        if(mode.equals("CR")) {

            serverIP = getIP("server");
            request = "CR:" + myName + ":" + ContactName + ":" + "ADDREMOTECONTACT" + myIP;
            byte[] cert = getMyCert(myName);
            sendrequestCR(request, serverIP);
            sendmessageCR(cert);
        }

        if(mode.equals("HP")) {

            serverIP = getIP("server");
            request = "HP:REQUEST:" + myName + ":" + ContactName + ":" + "ADDREMOTECONTACT";
            UdpEndpoints endpoints = sendrequestHP(request, serverIP);

            while(!responseflag) {
                try {

                    Thread.sleep(1000);

                } catch (java.lang.InterruptedException e) {}
            }

            endpoints.setUDP1(UDPendpoint1);
            endpoints.setUDP2(UDPendpoint2);

            initHP(endpoints);
            byte[] cert = getMyCert(myName);
            sendmessageHP(cert, endpoints);

        }


        Bundle bundle = new Bundle();
        bundle.putString("result", result);
        // Here we call send passing a resultCode and the bundle of extras
        rec.send(Activity.RESULT_OK, bundle);
    }

    //This receiver is used to receive the response of the Hole Punching request

    public class MyBroadcastReceiverARC extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            UDPendpoint1 = intent.getStringExtra("endpoint1");
            UDPendpoint2 = intent.getStringExtra("endpoint2");
            responseflag = true;
        }
    }

    //This method is used to send the encoded cert to the peer using Hole Punching

    public String sendmessageHP(byte[] mess, UdpEndpoints enps) {

        try {

            String addr1[] = enps.getUDP1().split(":");
            InetAddress destination = InetAddress.getByName(addr1[0]);
            int port = Integer.getInteger(addr1[1]);

            DatagramPacket certPacket = new DatagramPacket(mess, mess.length, destination, port);
            enps.getSock1().send(certPacket);
            enps.getSock1().send(certPacket);
            enps.getSock1().send(certPacket);


        }catch(java.io.IOException e) {globalresult = "io exception"; }

        return "SUCCESS";
    }

    //This method is used to send packets at the endpoints of the peer from the pre existing Udp sessions
    // with the endeuzvous server


    public void initHP(UdpEndpoints udpep) {

        try {

            String lineinfo[] = udpep.getUDP1().split("x");
            InetAddress destination = InetAddress.getByName(lineinfo[0].substring(1));
            int port1 = Integer.parseInt(lineinfo[1]);


            byte[] helloBuffer = "Hello".getBytes();
            DatagramPacket HelloPacket = new DatagramPacket(helloBuffer, helloBuffer.length, destination, port1);
            udpep.getSock1().send(HelloPacket);
            udpep.getSock1().send(HelloPacket);
            udpep.getSock1().send(HelloPacket);


            String lineinfo2[] = udpep.getUDP2().split("x");
            InetAddress destination2 = InetAddress.getByName(lineinfo2[0].substring(1));
            int port2 = Integer.parseInt(lineinfo2[1]);

            byte[] helloBuffer2 = "Hello".getBytes();
            DatagramPacket HelloPacket2 = new DatagramPacket(helloBuffer2, helloBuffer2.length, destination2, port2);
            udpep.getSock2().send(HelloPacket2);
            udpep.getSock2().send(HelloPacket2);
            udpep.getSock2().send(HelloPacket2);



        } catch(java.io.IOException e) {  }
    }


    //This method is used to send the Hole Punching request to the server and it returns the endpoints created

    public UdpEndpoints sendrequestHP(String mess, String toIP) {

        UdpEndpoints endp = new UdpEndpoints();

        try {

            PrintStream out;
            BufferedReader in;
            Socket socket = new Socket();
            InetSocketAddress socketaddr = new InetSocketAddress(toIP, 9999);
            while(!socket.isConnected()) {
                socket.connect(socketaddr, 0);
            }
            out = new PrintStream(socket.getOutputStream());
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out.println(mess);

            String line = in.readLine();
            String lineinfo[] = line.split(":");
            InetAddress destination = InetAddress.getByName(lineinfo[0]);
            int port1 = Integer.getInteger(lineinfo[1]);


            byte[]  helloBuffer = "Hello".getBytes();
            DatagramPacket HelloPacket = new DatagramPacket(helloBuffer, helloBuffer.length, destination, port1 );

            DatagramSocket Dsock1 = new DatagramSocket();
            Dsock1.setReuseAddress(true);
            Dsock1.send(HelloPacket);
            Dsock1.send(HelloPacket);
            Dsock1.send(HelloPacket);


            String line2 = in.readLine();
            String lineinfo2[] = line2.split(":");
            InetAddress destination2 = InetAddress.getByName(lineinfo2[0]);
            int port2 = Integer.getInteger(lineinfo2[1]);


            DatagramSocket Dsock2 = new DatagramSocket();
            Dsock2.setReuseAddress(true);
            DatagramPacket HelloPacket2 = new DatagramPacket(helloBuffer, helloBuffer.length, destination2, port2 );
            Dsock2.send(HelloPacket2);
            Dsock2.send(HelloPacket2);
            Dsock2.send(HelloPacket2);


            in.close();
            out.close();
            socket.close();

            endp.setSock1(Dsock1);
            endp.setSock2(Dsock2);

            return endp;

        }catch(java.io.IOException e) { globalresult = "sendrequestHP Exception"; }

        return endp;
    }

    //This method is used to send the encoded certificate to the peer if mode is CR

    public String sendmessageCR(byte[] mess) {

        try {

            ServerSocket ssocket = new ServerSocket(2222);
            Socket socket = ssocket.accept();
            OutputStream out2 = socket.getOutputStream();

            out2.write(mess);
            out2.close();
            socket.close();

        }catch(java.io.IOException e) { globalresult = "sendmessageCR io exception"; }

        return "SUCCESS";
    }

    //This method is used to send the CR request to the server

    public String sendrequestCR(String mess, String toIP) {


        try {
            PrintStream out;

            Socket socket = new Socket();
            InetSocketAddress socketaddr = new InetSocketAddress(toIP, 9999);
            while(!socket.isConnected()) {

                Thread.sleep(1000);
                socket.connect(socketaddr, 0);

            }
            out = new PrintStream(socket.getOutputStream());
            out.println(mess);
            out.flush();
            out.close();

            socket.close();

        }catch(java.io.IOException e) { globalresult = "sendrequestCR io exception"; }
         catch(java.lang.InterruptedException e) { }

        return "SUCCESS";
    }

    //This method is used to extract the certificate from the keystore


    public byte[] getMyCert(String mName) {

        byte[] cert = null;

        try {

            File file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES), "1.p12");
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream instreamKS = new FileInputStream(file);
            keyStore.load(instreamKS, "password".toCharArray());
            instreamKS.close();

            KeyStore.ProtectionParameter protparam = new KeyStore.PasswordProtection("password".toCharArray());
            KeyStore.PrivateKeyEntry mycert = (KeyStore.PrivateKeyEntry) keyStore.getEntry("me", protparam);

            X509Certificate Cert = (X509Certificate) mycert.getCertificate();

            cert = Cert.getEncoded();

            if(mycert!=null) {

                globalresult = "FAILED";
                //X509Certificate certificate = (X509Certificate) mycert.getCertificate();
                //cert = certificate.getEncoded();
            } else {
                globalresult = "DONE";
            }

        }catch(java.security.KeyStoreException e) { globalresult = "getmycert keystore exception"; }
        catch(java.io.FileNotFoundException e) { globalresult = "getmycert filenotfoundException"; }
        catch(java.security.NoSuchAlgorithmException e) { globalresult = "getmycert NosuchAlgo Exception"; }
        catch(java.io.IOException e) { globalresult = "getmycert IOexception"; }
        catch(java.security.cert.CertificateException e) { globalresult = "getmycert Certificate Exception"; }
        catch(java.security.UnrecoverableEntryException e) {  globalresult = "getmycert Unrecoverable entry Exception"; }

        return cert;
    }

    //This method is used to send the encoded certificate to the peer if mode is Normal/Normal1

    public String sendmessage(String mess, byte[] key, String addr) {

        String res=null;

        try {

            Socket socket = new Socket();
            InetSocketAddress socketaddr = new InetSocketAddress(addr,6666);
            while(!socket.isConnected()) {

                Thread.sleep(3000);
                socket.connect(socketaddr, 0);
            }

            ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

            output.writeObject(mess);
            output.flush();

            output.writeObject(key);
            output.flush();

            res = (String) input.readObject();

            output.close();
            input.close();
            socket.close();

        }catch(java.io.IOException e) { return "failed"; }
        catch(java.lang.ClassNotFoundException e) {}
        catch(java.lang.InterruptedException e) {}

        return res;
    }




    //  This method is used to send the ARC request to the peer if mode is Normal/Normal1

    public String sendrequest(String me, String contactIP) {

        byte[] cert;
        String message;
        String SE_result;

        cert = getMyCert(me);

        if(mode.equals("Normal1")) {

            message = "FRIEND:" + me + ":Normal1";
        } else {

            message = "FRIEND:" + me + ":Normal";
        }

        SE_result = sendmessage(message, cert, contactIP);


        return SE_result;
    }

    //This method is used to retrive the IP from the SQLite DB

    public String getIP(String name) {

        String IPAddress;
        SQLiteDatabase mydb;
        Cursor resultset;

        mydb = openOrCreateDatabase("mydata.db", Context.MODE_PRIVATE, null);
        resultset = mydb.query("IPTable",new String[] {"IP"}, "name=?",new String[] {name},null,null,null,null);
        //resultset = mydb.rawQuery("SELECT IP FROM IPTable WHERE name = ?", new String[] { name });
        resultset.moveToFirst();
        IPAddress = resultset.getString(0);
        mydb.close();
        //resultset.close();

        return IPAddress;


    }

}
