package com.iasonas.cryptovoip;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.ResultReceiver;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;


public class OutboundCallActivity extends AppCompatActivity {

    boolean flag = false;

    TextView tv;
    Button buttonCall, buttonExit;
    EditText address;
    EditText alias;
    EditText me;

    String myName;
    String serverIP;
    String mode;
    String contactName;

    Intent OutboundCallActivityService;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_outbound);

        buttonExit = (Button) findViewById(R.id.buttonEndCall);
        buttonCall = (Button) findViewById(R.id.buttonMakeCall);
        address = (EditText) findViewById(R.id.edittextIP);
        alias = (EditText) findViewById(R.id.edittextContact);
        me = (EditText) findViewById(R.id.edittextME);
        tv = (TextView) findViewById(R.id.textviewOutboundCall);


        OutboundCallActivityService = new Intent(this, OutboundCallActivityService.class);
        OutboundCallActivityService.putExtra("listener", new ResultReceiver(new Handler()) {
            @Override
            protected void onReceiveResult(int resultCode, Bundle resultData) {
                super.onReceiveResult(resultCode, resultData);

                if (resultCode == Activity.RESULT_OK) {

                    String resultValue = resultData.getString("result");
                    Toast.makeText(OutboundCallActivity.this, resultValue, Toast.LENGTH_SHORT).show();
                    tv.setText(resultValue);

                }
            }
        });


        buttonCall.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {


                contactName = alias.getText().toString();
                myName = me.getText().toString();
                serverIP = address.getText().toString();


                OutboundCallActivityService.putExtra("Cname", contactName);
                OutboundCallActivityService.putExtra("Myname", myName);
                OutboundCallActivityService.putExtra("IP", serverIP);
                startService(OutboundCallActivityService);

            }
        });

        buttonExit.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                Intent intent = new Intent();
                intent.setAction("com.example.iasonas.cryptoipfinal.ENDOUTCALL");
                LocalBroadcastManager.getInstance(OutboundCallActivity.this).sendBroadcast(intent);

                finish();
            }
        });

    }


}
