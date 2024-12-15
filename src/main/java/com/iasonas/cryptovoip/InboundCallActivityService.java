package com.iasonas.cryptovoip;

import android.app.Activity;
import android.app.IntentService;
import android.app.Notification;
import android.app.PendingIntent;
import android.content.Intent;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.AudioTrack;
import android.os.Binder;
import android.os.Bundle;
import android.os.Environment;
import android.os.IBinder;
import android.os.ResultReceiver;
import android.security.KeyPairGeneratorSpec;

import androidx.core.app.NotificationCompat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.x500.X500Principal;

import static android.security.keystore.KeyProperties.KEY_ALGORITHM_RSA;

public class InboundCallActivityService extends IntentService {

    HandshakeResult hResult;
    String IP;
    String contactName;
    boolean status = false;
    String result;
    String mode;
    UdpEndpoints endpoints;
    String myalias;
    String UDPendpoint1;
    String UDPendpoint2;
    String resultglobal;
    String serverIP;
    private final ServiceBinder binder = new ServiceBinder();
    public static boolean isRunning = true;



    int sampleRate = 16000;
    int channelConfig = AudioFormat.CHANNEL_CONFIGURATION_MONO;
    int audioFormat = AudioFormat.ENCODING_PCM_16BIT;
    int minBufSize = AudioRecord.getMinBufferSize(sampleRate, channelConfig, audioFormat);

    public InboundCallActivityService() {
        super("test-service");
    }


    @Override
    protected void onHandleIntent(Intent intent) {

        status = true;

        Intent notificationIntent = new Intent(this, StopCallActivityIn.class);

        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0,
                notificationIntent, 0);

        Notification notification = new NotificationCompat.Builder(this)
                .setSmallIcon(R.mipmap.ic_launcher_round)
                .setContentTitle("OutBoundCall")
                .setContentText("CallInProgress")
                .setContentIntent(pendingIntent).build();

        startForeground(8888888, notification);

        ResultReceiver rec = intent.getParcelableExtra("listener");

        mode = intent.getStringExtra("mode");

        if (mode.equals("Normal") || mode.equals("Normal1") || mode.equals("CR")) {

            contactName = intent.getStringExtra("fromAlias");
            IP = intent.getStringExtra("contactIP");

        } else if (mode.equals("HP")) {

            contactName = intent.getStringExtra("fromAlias");
            myalias = intent.getStringExtra("toAlias");
            UDPendpoint1 = intent.getStringExtra("endpoint1");
            UDPendpoint2 = intent.getStringExtra("endpoint2");

            //String serverIP = getIP("server");
            String response = "HP:RESPONSE:" + myalias + ":" + contactName + ":" + "CALL";
            endpoints = sendHP(response, "192.168.1.3");
            endpoints.setUDP1(UDPendpoint1);
            endpoints.setUDP2(UDPendpoint2);

            initHP(endpoints);
        }


        InHandshake IH = new InHandshake(IP, contactName, mode, endpoints);
        hResult = IH.doHandshakeHP();
        HandshakeResult h = new HandshakeResult();


        Thread thread1 = new Thread(new MakeCallHPIn(h, endpoints, "RECEIVE"));
        Thread thread2 = new Thread(new MakeCallHPIn(h, endpoints, "SEND"));

        //thread1.start();
        //thread2.start();

        while(isRunning) {

            try {

                Thread.sleep(4000);

            } catch (java.lang.InterruptedException e) {}

        }

        Bundle bundle = new Bundle();
        bundle.putString("result", hResult.getstatus());
        // Here we call send passing a resultCode and the bundle of extras
        rec.send(Activity.RESULT_OK, bundle);
    }


    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    public class ServiceBinder extends Binder {
        public InboundCallActivityService getService() {
            return InboundCallActivityService.this;
        }
    }


    public void stopService() {

        isRunning = false;
        this.onDestroy();
        stopForeground(true);
    }

    public void makeCall(final HandshakeResult handshakeR, final UdpEndpoints endps, final String cIP) {

        Thread streamThread2 = new Thread(new Runnable() {

            @Override
            public void run() {

                try {

                    AudioTrack track;
                    track = new AudioTrack(AudioManager.MODE_NORMAL, 16000, AudioFormat.CHANNEL_CONFIGURATION_MONO,
                            AudioFormat.ENCODING_PCM_16BIT, minBufSize, AudioTrack.MODE_STREAM);


                    //////////////////////////////////////////////////////////////////////////////

                    //////////////////////////////////////////////////////////////////////////////

                    byte[] buffer2 = new byte[minBufSize];
                    DatagramSocket socket2 = null;
                    final InetAddress destination = InetAddress.getByName(IP);
                    DatagramPacket packet = new DatagramPacket(buffer2, buffer2.length);

                    if (mode.equals("Normal") || mode.equals("CR")) {

                        socket2 = new DatagramSocket(4444);
                        while (!socket2.isConnected()) {

                            socket2.connect(destination, 6666);

                        }


                    }
                    if (mode.equals("Normal1")) {

                        socket2 = new DatagramSocket(4444);
                        while (!socket2.isConnected()) {
                            socket2.connect(destination, 5555);
                        }
                    }

                    track.play();

                    while (status) {

                        if (mode.equals("Normal") || mode.equals("CR") || mode.equals("Normal1")) {
                            socket2.receive(packet);
                        } else {

                            endps.getSock2().receive(packet);
                        }
                        ////////////////////////////////////////////////


                        track.write(buffer2, 0, buffer2.length);
                        track.flush();


                    }

                    track.stop();
                    track.release();
                    socket2.disconnect();
                    socket2.close();


                } catch (UnknownHostException e) {
                    resultglobal = "makeCallT2 : UnknownHostException";
                } catch (SocketException e) {
                    resultglobal = "makeCallT2 : SocketException";
                } catch (IOException e) {
                    resultglobal = "makeCallT2 : IOException";
                }

            }

        });

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
