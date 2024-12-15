package com.iasonas.cryptovoip;

/*
This class is used to start the server
 */

import android.app.IntentService;
import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Binder;
import android.os.Environment;
import android.os.IBinder;
import android.os.PowerManager;
import android.view.WindowManager;

import androidx.core.app.NotificationCompat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;


public  class ServerService extends Service {

    boolean isRunning = true;
    private final ServiceBinder2 binder = new ServiceBinder2();
    private Thread backgroundThread;


    private Runnable myTask = new Runnable() {
        public void run() {

            ServerSocket mServerSocket;

            try {
                mServerSocket = new ServerSocket(6666);
                while (isRunning) {
                    Socket socket = mServerSocket.accept();
                    handle(socket);
                }
                mServerSocket.close();
            } catch (SocketException e) {
                // The server was stopped; ignore.
            } catch (IOException e) {}


        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId){

        this.backgroundThread.start();

        return START_STICKY;
    }

    @Override
    public void onCreate() {

        this.backgroundThread = new Thread(myTask);

        Intent notificationIntent = new Intent(this, StopServiceActivity2.class);

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

        isRunning = false;
        super.onDestroy();

    }

    public void stopService() {

        isRunning = false;
        this.onDestroy();
        stopForeground(true);
        stopSelf();
    }



    public class ServiceBinder2 extends Binder {
        public ServerService getService() {
            return ServerService.this;
        }
    }

    private void handle(Socket socket) {

        try {
            PrintStream output = new PrintStream(socket.getOutputStream());
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            String lineS;

            output.println("HELLO");
            output.flush();
            lineS = input.readLine();

            if(lineS.startsWith("CALL")) {

                String Cname;
                String mode;
                String cIP;

                String info[] = lineS.split(":");
                Cname = info[1];
                cIP = info[2];
                mode = info[3];

                output.println("SUCCESS");
                output.flush();

                input.close();
                output.close();
                socket.close();

                Intent InboundCallIntent = new Intent(this, InboundCallActivity.class);
                InboundCallIntent.putExtra("mode", mode);
                InboundCallIntent.putExtra("Name", Cname);
                InboundCallIntent.putExtra("ContactIP",cIP);
                InboundCallIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(InboundCallIntent);

            } else {

                output.println("BAD REQUEST");
                input.close();
                output.close();
                socket.close();

            }

        }catch (java.io.IOException e) {}
    }


}
