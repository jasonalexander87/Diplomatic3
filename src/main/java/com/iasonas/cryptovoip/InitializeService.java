package com.iasonas.cryptovoip;

import android.app.Activity;
import android.app.IntentService;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.os.Environment;
import android.os.ResultReceiver;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyStore;
import java.util.Enumeration;

/**
 This class is used to actually perform the insertion of a peers address or intitialize the aplication to use a server
 */

public class InitializeService extends IntentService {

    String result;
    boolean flag;
    String response;
    String serverIP;
    Intent Server;
    Intent Serverv2;

    public InitializeService() {
        super("test-service");
    }

    @Override
    protected void onHandleIntent(Intent intent) {

        Server = new Intent(this, ServerService.class);
        Serverv2 = new Intent(this, Service2.class);

        ResultReceiver  rec = intent.getParcelableExtra("listener");

        String mode = intent.getStringExtra("mode");

        if(mode.equals("ADD")) {

            String aliasName = intent.getStringExtra("aliasName");
            String aliasNameIP = intent.getStringExtra("aliasNameIP");
            boolean resultS;

            resultS = addToDB(aliasName, aliasNameIP);


            Bundle bundle = new Bundle();
            if(!resultS) {
                bundle.putString("result", "ADD_FAILED");
            }
            bundle.putString("result", "ADD_DONE");

            rec.send(Activity.RESULT_OK, bundle);
        }

        if(mode.equals("SERVER")) {

            String serverIP = intent.getStringExtra("serverIP");
            String myalias = intent.getStringExtra("myalias");
            addToDB("server", serverIP);

            Serverv2.putExtra("myAlias", myalias);
            this.startService(Serverv2);

            /*
            String result = register(myalias, serverIP);

            if(result.equals("REGISTER_FAILED")) {

                Bundle bundle = new Bundle();
                bundle.putString("result", result);

                rec.send(Activity.RESULT_OK, bundle);

            } else if(result.equals("REGISTER_SUCCESS")) {

                result = retriveFromServer(serverIP);

                Bundle bundle = new Bundle();
                bundle.putString("result", result);
                rec.send(Activity.RESULT_OK, bundle);

            }
            */
        }


    }

    //This method opens the sqlite DB and creates an entry of alias//IP

    public boolean addToDB(String Cname, String address) {

        Context con = getApplicationContext();
        SharedPreferences sharedPrefs = con.getSharedPreferences(getString(R.string.sharedPrefs), Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPrefs.edit();
        if(sharedPrefs.contains(Cname)) { return false; }

        editor.putString(Cname, address);


        editor.apply();

        return true;
    }

    //This method registers a user to the rendeuvouz server and starts the apropriate service

    public String register(String me, String Serverip ) {

        String myIP = retrieveMyIp(me);
        String message = "POST:" + me + ":" + myIP;
        String response = sendmessage(message, Serverip);
        if(response.equals("public")) {

            addToDB(me, myIP);
            startService(Server);

        } else if(response.equals("private")) {

            addToDB(me, "0.0.0.0");
            Serverv2.putExtra("myAlias", me);
            this.startService(Serverv2);

        } else if(response.equals("SENDMESSAGE_FAILED")) {

            return "REGISTER_FAILED";

        }

        return "REGISTER_SUCCESS";
    }

    //This method retrieves the Ip from users device

    private String retrieveMyIp(String myalias) {

        String res;
        Context con = getApplicationContext();
        SharedPreferences sharedPrefs = con.getSharedPreferences(getString(R.string.sharedPrefs), Context.MODE_PRIVATE);

        if(sharedPrefs.contains(myalias)) {

            res = sharedPrefs.getString(myalias, "0.0.0.0");
            return res;

        } else {

            try {
                for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                    NetworkInterface intf = en.nextElement();
                    for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements(); ) {
                        InetAddress inetAddress = enumIpAddr.nextElement();
                        if (!inetAddress.isLoopbackAddress() && inetAddress instanceof Inet4Address) {
                            return inetAddress.getHostAddress();

                        }
                    }
                }
            } catch (SocketException e) {
                result = "retriveMyIp socket exception";
            }
            return null;
        }
    }

    //This method actually sends the message to the server

    public String sendmessage( String mess, String SerIP) {

        String line;

        try {

            BufferedReader in;
            PrintStream out;

            Socket socket = new Socket();
            InetSocketAddress socketaddr = new InetSocketAddress(SerIP, 9999);
            while(!socket.isConnected()) {
                socket.connect(socketaddr, 0);
            }

            out = new PrintStream(socket.getOutputStream());
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out.println(mess);
            out.flush();
            out.close();
            line = in.readLine();


            in.close();
            socket.close();


        }catch(java.io.IOException e) { return "SENDMESSAGE_FAILED"; }

        return line;
    }

    //This method tries to receive the addresses from all the entries in the keystore

    public String retriveFromServer(String SIP) {


        try {

            File file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES), "keystore.p12");
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream instreamKS = new FileInputStream(file);
            keyStore.load(instreamKS, "password".toCharArray());
            instreamKS.close();

            for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements();) {

                String alias = aliases.nextElement();
                String message = "GET:" + alias ;
                String response = sendmessage(message, SIP);

                if(!response.equals("Not Found")) { addToDB(alias, response); }

            }
        }catch (java.security.KeyStoreException e) { return "RFS_KeyStoreException";}
        catch (java.io.FileNotFoundException e) { return "RFS_FileNotFoundException";}
        catch (java.security.NoSuchAlgorithmException e) { return "RFS_NoSuchAlgorithmException";}
        catch (java.io.IOException e) { return "RFS_IOException";}
        catch (java.security.cert.CertificateException e) { return "RFS_CertificateException";}

        return "RFS_SUCCESS";
    }

}


