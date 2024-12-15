package com.iasonas.cryptovoip;

/*
This method either adds the address of a contact or initializes the application to use a server
 */

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.ResultReceiver;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;


public class Initialize extends AppCompatActivity {


    //public MyTestReceiver receiverForTest;

    Button buttonAdd, buttonExit, buttonAddServer ;
    EditText alias;
    EditText aliasIP;
    EditText myAlias;

    String result;
    boolean flag;
    String response;
    String serverIP;
    String aliasName;
    String aliasNameIP;
    String myalias;

    Intent InitializeService;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_initialize);


        InitializeService = new Intent(this, InitializeService.class);
        //InitializeService.putExtra("receiver", receiverForTest);


        buttonAddServer = findViewById(R.id.buttonAddServer);
        buttonAdd = findViewById(R.id.buttonAddIP);
        buttonExit = findViewById(R.id.buttonExitInitialize);
        alias = findViewById(R.id.edittextAlias);
        aliasIP = findViewById(R.id.edittextIP);
        myAlias = findViewById(R.id.edittextMyAlias);

        //setupServiceReceiver();


        buttonAdd.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                aliasName = alias.getText().toString();
                aliasNameIP = aliasIP.getText().toString();

                InitializeService.putExtra("mode", "ADD");
                InitializeService.putExtra("aliasName", aliasName);
                InitializeService.putExtra("aliasNameIP", aliasNameIP);

                InitializeService.putExtra("listener", new ResultReceiver(new Handler()) {
                    @Override
                    protected void onReceiveResult(int resultCode, Bundle resultData) {
                        super.onReceiveResult(resultCode, resultData);

                        if (resultCode == Activity.RESULT_OK) {

                            String resultValue = resultData.getString("result");
                            Toast.makeText(Initialize.this, resultValue, Toast.LENGTH_SHORT).show();

                        }
                    }
                });

                startService(InitializeService);
            }
        });

        buttonAddServer.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                myalias = myAlias.getText().toString();
                serverIP = aliasIP.getText().toString();

                InitializeService.putExtra("mode", "SERVER");
                InitializeService.putExtra("myalias", myalias);
                InitializeService.putExtra("serverIP", serverIP);
                startService(InitializeService);
            }
        });

        buttonExit.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                finish();

            }
        });

    }

}
