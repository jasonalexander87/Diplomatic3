package com.iasonas.cryptovoip;

/*
 This class is used to take the parameters from the user and to start the add remote contact service tha sends a
 remote friend request to the selected alias alongside the certificate
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

import java.net.DatagramSocket;


public class AddRemoteContact extends AppCompatActivity {


    Button sendRequest;
    Button exit;
    EditText myAliasET;
    EditText cAliasET;

    DatagramSocket Dsock1;
    DatagramSocket Dsock2;

    String ContactName;
    String myName;
    String result;

    String serverIP;
    byte[] cert;
    String mode;
    boolean flag;

    Intent AddRemoteContactService;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_addremotecontact);

        exit = findViewById(R.id.buttonExitAddRemoteContact);
        sendRequest = findViewById(R.id.buttonAddRemoteContact);
        myAliasET = findViewById(R.id.edittextMyAlias);
        cAliasET = findViewById(R.id.edittextAddRemoteContact);



        AddRemoteContactService = new Intent(this, AddRemoteContactService.class);
        AddRemoteContactService.putExtra("listener", new ResultReceiver(new Handler()) {
            @Override
            protected void onReceiveResult(int resultCode, Bundle resultData) {
                super.onReceiveResult(resultCode, resultData);

                if (resultCode == Activity.RESULT_OK) {

                    String resultValue = resultData.getString("result");
                    Toast.makeText(AddRemoteContact.this, resultValue, Toast.LENGTH_SHORT).show();

                }
            }
        });


        sendRequest.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                ContactName = cAliasET.getText().toString();
                myName = myAliasET.getText().toString();

                AddRemoteContactService.putExtra("Cname", ContactName);
                AddRemoteContactService.putExtra("Myname", myName);
                startService(AddRemoteContactService);


            }
        });

        exit.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                finish();
            }
        });
    }



}



