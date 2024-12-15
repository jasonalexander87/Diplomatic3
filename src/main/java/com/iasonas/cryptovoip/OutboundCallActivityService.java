package com.iasonas.cryptovoip;

import android.app.Activity;
import android.app.IntentService;
import android.app.Notification;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.media.AudioFormat;
import android.media.AudioRecord;
import android.media.MediaRecorder;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.ResultReceiver;
import android.util.Log;
import android.widget.Toast;

import androidx.core.app.NotificationCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class OutboundCallActivityService extends IntentService {


    HandshakeResult hResult;
    String resultglobal;

    String myName;
    String cIP;
    String serverIP;
    String myIP;
    String mode = "Normal";
    String request;
    int sizeC;

    String UDPendpoint1;
    String UDPendpoint2;
    boolean responseflag;
    DatagramSocket Dsock1;
    DatagramSocket Dsock2;
    UdpEndpoints endpoints;
    //HandshakeResult hResult;
    private final ServiceBinder binder = new ServiceBinder();
    public static boolean isRunning = true;

    DatagramSocket sock;
    String contactName;
    boolean status = false;
    int sampleRate = 16000;
    int channelConfig = AudioFormat.CHANNEL_CONFIGURATION_MONO;
    int audioFormat = AudioFormat.ENCODING_PCM_16BIT;
    int minBufSize = AudioRecord.getMinBufferSize(sampleRate, channelConfig, audioFormat);

    public OutboundCallActivityService() {
        super("test-service");
    }

    @Override
    protected void onHandleIntent(Intent intent) {

        Intent notificationIntent = new Intent(this, StopCallActivity.class);

        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0,
                notificationIntent, 0);

        Notification notification = new NotificationCompat.Builder(this)
                .setSmallIcon(R.mipmap.ic_launcher_round)
                .setContentTitle("OutBoundCall")
                .setContentText("CallInProgress")
                .setContentIntent(pendingIntent).build();

        startForeground(8888888, notification);


        LocalBroadcastManager localBroadcastManager = LocalBroadcastManager.getInstance(this);
        BroadcastReceiver br = new MyBroadcastReceiverServer();
        IntentFilter filter = new IntentFilter();
        filter.addAction("com.example.iasonas.cryptoipfinal.HPCALL");
        localBroadcastManager.registerReceiver(br, filter);


        status = true;

        ResultReceiver rec = intent.getParcelableExtra("listener");

        contactName = intent.getStringExtra("Cname");
        myName = intent.getStringExtra("Myname");

        cIP = intent.getStringExtra("IP");
        cIP = "192.168.1.2";
        myIP = "192.168.1.4";
        //myIP = getIP(myName);
        // cIP = getIP(contactName);
        serverIP = "192.168.1.3";

        if(myIP.equals("0.0.0.0")&cIP.equals("0.0.0.0")) {

            mode = "HP";

        } else if(cIP.equals("0.0.0.0")) {

            mode = "CR";

        } else if(myIP.equals("0.0.0.0")){

            mode = "Normal1";

        } else {

            mode = "Normal";

        }

        mode = "HP";

        if(mode.equals("Normal") || mode.equals("Normal1")) {

            resultglobal = sendcallrequest(myName, myIP, cIP);

        }
        if(mode.equals("CR")) {

            request = "CR:" + myName + ":" + contactName + ":" + "OutboundCallActivity" + myIP;

            sendrequestCR(request, serverIP);

        } else if(mode.equals("HP")) {

            request = "HP:REQUEST:" + myName + ":" + contactName + ":" + "CALL";
            endpoints = sendHP(request, serverIP);

            while(!responseflag) {

                try {

                    Thread.sleep(1000);

                } catch (java.lang.InterruptedException e) {}

            }
            endpoints.setUDP1(UDPendpoint1);
            endpoints.setUDP2(UDPendpoint2);

            initHP(endpoints);
        }

        Log.d("START","START");

        OutHandshake OH = new OutHandshake(cIP, contactName, mode, endpoints);
        hResult = OH.doHandshakeHP();
        Log.d("STATUS",hResult.getstatus());
        Log.d("KEYLENGHT",hResult.getIV().toString());
        Log.d("STATUS",hResult.getKey().toString());


        Bundle bundle = new Bundle();
        bundle.putString("result", hResult.getstatus());
        // Here we call send passing a resultCode and the bundle of extras
        rec.send(Activity.RESULT_OK, bundle);

        Thread thread1 = new Thread(new MakeCallHPIn3(h, endpoints2, "RECEIVE"));
        Thread thread2 = new Thread(new MakeCallHPIn3(h, endpoints2, "SEND"));

        thread1.start();
        thread2.start();

        while(isRunning) {

            try {

                Thread.sleep(100);

            } catch (java.lang.InterruptedException e) {}

        }


    }

    public void stopService() {

        isRunning = false;
        this.onDestroy();
        stopForeground(true);
    }

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    public class ServiceBinder extends Binder {
        public OutboundCallActivityService getService() {
            return OutboundCallActivityService.this;
        }
    }

    public class MyBroadcastReceiverServer extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {

            Toast.makeText(OutboundCallActivityService.this, "BR", Toast.LENGTH_SHORT).show();
            UDPendpoint1 = intent.getStringExtra("endpoint1");
            UDPendpoint2 = intent.getStringExtra("endpoint2");
            responseflag = true;
        }
    }


    public void sendrequestCR(String mess, String serverIp) {

        try {

            PrintStream out;

            Socket socket = new Socket();
            InetSocketAddress socketaddr = new InetSocketAddress(serverIp, 9999);
            while(!socket.isConnected()) {
                socket.connect(socketaddr, 0);
            }
            out = new PrintStream(socket.getOutputStream());

            ///////////////////////////////////////////////////////////////////////////


            out.println(mess);
            out.flush();
            out.close();

            socket.close();

        }catch(java.io.IOException e) { resultglobal = "sendrequestCR IO exception"; }

    }

    public String sendcallrequest(String mName, String mIP, String contactIP) {

        String request = null;
        String result = null;

        if(mode.equals("Normal")) {

            request = "CALL:" + mName + ":" + mIP + ":Normal";
        } else if(mode.equals("Normal1")) {

            request = "CALL:" + mName + ":" + mIP + ":Normal1";
        }

        try{

            Socket socket = new Socket();
            InetSocketAddress addr = new InetSocketAddress(contactIP, 6666);
            while(!socket.isConnected()) {
                socket.connect(addr, 0);
            }

            PrintStream output = new PrintStream(socket.getOutputStream());
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            output.println(request);
            output.flush();

            result = input.readLine();

            output.close();
            socket.close();

            return result;


        }catch(IOException e) { return "sendcallrequest : IOException";  }

    }

    public UdpEndpoints sendHP(String mess, String serIP) {

        Socket socket;
        PrintStream output;
        BufferedReader input;
        UdpEndpoints endp = new UdpEndpoints();


        try {

            socket = new Socket(serIP, 9999);
            output = new PrintStream(socket.getOutputStream());
            input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            output.println(mess);

            String line = input.readLine();
            String lineinfo[] = line.split(":");

            InetAddress destination = InetAddress.getByName(serIP);
            int port1 = Integer.parseInt(lineinfo[1]);

            byte[] helloBuffer = "HELLO".getBytes();
            DatagramPacket helloPacket = new DatagramPacket(helloBuffer, helloBuffer.length, destination, port1);

            DatagramSocket Dsock1 = new DatagramSocket();
            Dsock1.send(helloPacket);
            Dsock1.send(helloPacket);
            Dsock1.send(helloPacket);
            Dsock1.send(helloPacket);
            Dsock1.send(helloPacket);
            Dsock1.send(helloPacket);



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

            String line2 = input.readLine();
            String lineinfo2[] = line2.split(":");

            InetAddress destination2 = InetAddress.getByName(serIP);
            int port2 = Integer.parseInt(lineinfo2[1]);

            byte[] helloBuffer2 = "HELLO".getBytes();
            DatagramPacket helloPacket2 = new DatagramPacket(helloBuffer2, helloBuffer2.length, destination2, port2);

            DatagramSocket Dsock2 = new DatagramSocket();
            Dsock2.send(helloPacket2);
            Dsock2.send(helloPacket2);
            Dsock2.send(helloPacket2);
            Dsock2.send(helloPacket2);
            Dsock2.send(helloPacket2);
            Dsock2.send(helloPacket2);



            input.close();
            output.close();
            socket.close();

            endp.setSock1(Dsock1);
            endp.setSock2(Dsock2);

            return endp;

        } catch (java.io.IOException e) { }

        return endp;
    }

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
            udpep.getSock2().send(HelloPacket2);
            udpep.getSock2().send(HelloPacket2);
            udpep.getSock2().send(HelloPacket2);




        } catch(java.io.IOException e) {  }
    }

}
