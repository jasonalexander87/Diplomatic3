package com.iasonas.cryptovoip;

import android.app.Activity;
import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.Socket;


public  class Service2 extends Service {

    String serverIP;
    Socket socket;
    String message;
    PrintStream output;
    BufferedReader input;
    String line;
    String myalias;
    boolean isRunning = true;
    private Thread backgroundThread;
    private final ServiceBinder binder = new ServiceBinder();


    private Runnable myTask = new Runnable() {
        public void run() {

            try {

                serverIP = getIP("server");
                socket = new Socket("192.168.1.3", 9999);
                output = new PrintStream(socket.getOutputStream());
                input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                message = "KEEPALIVE:"+ myalias;
                output.println(message);

                while(isRunning) {

                    line=input.readLine();
                    handle(line);

                }


            } catch(java.io.IOException e) {}

        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId){

        myalias = intent.getStringExtra("myAlias");
        this.backgroundThread.start();

        return START_STICKY;
    }

    @Override
    public void onCreate() {

        this.backgroundThread = new Thread(myTask);


        Intent notificationIntent = new Intent(this, StopServiceActivity.class);

        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0,
                notificationIntent, 0);

        Notification notification = new NotificationCompat.Builder(this)
                .setSmallIcon(R.mipmap.ic_launcher_round)
                .setContentTitle("CryptoIP")
                .setContentText("Service running")
                .setContentIntent(pendingIntent).build();

        startForeground(12345678, notification);


    }

    @Override
    public void onDestroy() {

        super.onDestroy();
        isRunning = false;

    }

    public void stopService() {

        isRunning = false;
        this.onDestroy();
        stopForeground(true);
        stopSelf();
    }



    public class ServiceBinder extends Binder {
        public Service2 getService() {
            return Service2.this;
        }
    }


    public String getIP(String name) {

        String IPAddress;
        Context con = getApplicationContext();
        SharedPreferences sharedPrefs = con.getSharedPreferences(getString(R.string.sharedPrefs), Context.MODE_PRIVATE);
        IPAddress = sharedPrefs.getString(name, "0.0.0.0");

        return IPAddress;
    }


    public String handle(String inline) {

        String[] result;
        result = inline.split(":");

        if(result[0].equals("CR")) {

            if(result[2].equals("CALL")) {

                Intent CallIntent = new Intent(this, InboundCallActivity.class);
                CallIntent.putExtra("mode", result[0]);
                CallIntent.putExtra("fromAlias", result[3]);
                CallIntent.putExtra("IP", result[4]);
                startActivity(CallIntent);

            } else if(result[2].equals("ADDREMOTECONTACT")) {

                Intent ARCIntent = new Intent(this, ContactRequest.class);
                ARCIntent.putExtra("mode", result[0]);
                ARCIntent.putExtra("fromAlias", result[3]);
                ARCIntent.putExtra("IP", result[4]);
                startActivity(ARCIntent);

            } else if(result[2].equals("WEBOFTRUST")) {

                Intent WOTIntent = new Intent(this, Validate.class);
                WOTIntent.putExtra("mode", result[0]);
                WOTIntent.putExtra("fromAlias", result[3]);
                WOTIntent.putExtra("IP", result[4]);
                startActivity(WOTIntent);

            }


            return "CRREQUEST FORWARDED";

        } else if(inline.startsWith("HP:RESPONSE")) {

            Intent intent = new Intent();
            intent.setAction("com.example.iasonas.cryptoipfinal.HP"+result[2]);
            intent.putExtra("mode", result[0]);
            intent.putExtra("type", result[1]);
            intent.putExtra("fromAlias", result[3]);
            intent.putExtra("toAlias", result[4]);
            intent.putExtra("endpoint1", result[5]);
            intent.putExtra("endpoint2", result[6]);
            LocalBroadcastManager.getInstance(this).sendBroadcast(intent);

        } else if(inline.startsWith("HP:REQUEST")) {

            if(result[2].equals("CALL")) {

                Intent CallIntent = new Intent(this, InboundCallActivity.class);
                CallIntent.putExtra("mode", result[0]);
                CallIntent.putExtra("type", result[1]);
                CallIntent.putExtra("fromAlias", result[3]);
                CallIntent.putExtra("toAlias", result[4]);
                CallIntent.putExtra("endpoint1", result[5]);
                CallIntent.putExtra("endpoint2", result[6]);

                CallIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

                startActivity(CallIntent);

            } else if(result[2].equals("ADDREMOTECONTACT")) {


                Intent ARCIntent = new Intent(this, ContactRequest.class);
                ARCIntent.putExtra("mode", result[0]);
                ARCIntent.putExtra("type", result[1]);
                ARCIntent.putExtra("fromAlias", result[3]);
                ARCIntent.putExtra("toAlias", result[4]);
                ARCIntent.putExtra("endpoint1", result[5]);
                ARCIntent.putExtra("endpoint2", result[6]);

                startActivity(ARCIntent);

            } else if(result[2].equals("WEBOFTRUST")) {

                Intent WOTIntent = new Intent(this, Validate.class);
                WOTIntent.putExtra("mode", result[0]);
                WOTIntent.putExtra("type", result[1]);
                WOTIntent.putExtra("fromAlias", result[3]);
                WOTIntent.putExtra("toAlias", result[4]);
                WOTIntent.putExtra("endpoint1", result[5]);
                WOTIntent.putExtra("endpoint2", result[6]);

                startActivity(WOTIntent);

            }

        }

        return "success";

    }



}




