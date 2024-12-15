package com.iasonas.cryptovoip;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.PowerManager;
import android.os.ResultReceiver;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.net.DatagramSocket;

public class InboundCallActivity extends AppCompatActivity {


    boolean flag = false;

    Button buttonAnswer, buttonIgnore;
    TextView contact;
    String IP;
    String contactName;
    String result;
    String mode;

    String myalias;
    String serverIP;
    String response;
    String UDPendpoint1;
    String UDPendpoint2;
    DatagramSocket Dsock1;
    DatagramSocket Dsock2;

    private PowerManager.WakeLock wl;

    Intent InboundCallActivityService;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_inbound);

        PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
        wl = pm.newWakeLock(PowerManager.FULL_WAKE_LOCK,"Mytag:");
        wl.acquire();

        this.getWindow().setFlags(WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON, WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON);
        contact = (TextView) findViewById(R.id.textviewInboundCall);
        contact.setText(contactName);

        buttonAnswer = (Button) findViewById(R.id.buttonAnswerCall);
        buttonIgnore = (Button) findViewById(R.id.buttonIgnoreCall);

        InboundCallActivityService = new Intent(this, InboundCallActivityService.class);
        InboundCallActivityService.putExtra("listener", new ResultReceiver(new Handler()) {
            @Override
            protected void onReceiveResult(int resultCode, Bundle resultData) {
                super.onReceiveResult(resultCode, resultData);

                if (resultCode == Activity.RESULT_OK) {

                    String resultValue = resultData.getString("result");
                    Toast.makeText(InboundCallActivity.this, resultValue, Toast.LENGTH_SHORT).show();
                    contact.setText(resultValue);


                }
            }
        });

        Intent InboundCall = getIntent();
        mode = InboundCall.getStringExtra("mode");

        if(mode.equals("Normal")) {

            contactName = InboundCall.getStringExtra("Name");
            IP = InboundCall.getStringExtra("ContactIP");

            contact.setText(mode + contactName + IP);



        }else if(mode.equals("CR")) {

            contactName = InboundCall.getStringExtra("fromAlias");
            IP = InboundCall.getStringExtra("IP");



        } else if(mode.equals("Normal1")) {

            contactName = InboundCall.getStringExtra("Name");
            IP = InboundCall.getStringExtra("ContactIP");




        } else if(mode.equals("HP")) {

            contactName = InboundCall.getStringExtra("fromAlias");
            myalias = InboundCall.getStringExtra("toAlias");
            UDPendpoint1 = InboundCall.getStringExtra("endpoint1");
            UDPendpoint2 = InboundCall.getStringExtra("endpoint2");


        }


        buttonAnswer.setOnClickListener(startListener);
        buttonIgnore.setOnClickListener(stopListener);
    }

    private final View.OnClickListener stopListener = new View.OnClickListener() {

        @Override
        public void onClick(View arg0){


            wl.release();
            finish();
        }

    };

    private final View.OnClickListener startListener = new View.OnClickListener() {

        @Override
        public void onClick(View arg0){


            InboundCallActivityService.putExtra("mode", mode);
            InboundCallActivityService.putExtra("fromAlias", contactName);
            InboundCallActivityService.putExtra("contactIP", IP);
            InboundCallActivityService.putExtra("toAlias", myalias);
            InboundCallActivityService.putExtra("endpoint1", UDPendpoint1);
            InboundCallActivityService.putExtra("endpoint2", UDPendpoint2);

            startService(InboundCallActivityService);

        }

    };


}

