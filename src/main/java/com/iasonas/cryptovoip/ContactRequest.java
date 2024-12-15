package com.iasonas.cryptovoip;

/*
This class is used to start the intent service that handles the ARC Request produced by the AddRemoteContact
 */

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.ResultReceiver;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.net.DatagramSocket;


public class ContactRequest extends AppCompatActivity {


    Button buttonAccept, buttonDeny;
    String name;
    byte[] key = null;
    String result;
    String mode;
    String from;
    String fromIP;
    boolean flag;
    String serverIP;
    String myName;

    Intent ContactRequestService;
    String UDPendpoint1;
    String UDPendpoint2;
    DatagramSocket Dsock1;
    DatagramSocket Dsock2;
    int size;
    String sizeS;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_contactrequest);

        buttonAccept = (Button) findViewById(R.id.buttonAddContact);
        buttonDeny = (Button) findViewById(R.id.buttonExitAddContact);
        TextView displayContact = (TextView)findViewById(R.id.textviewAddContactRequest);

        ContactRequestService = new Intent(this, ContactRequestService.class);
        ContactRequestService.putExtra("listener", new ResultReceiver(new Handler()) {
            @Override
            protected void onReceiveResult(int resultCode, Bundle resultData) {
                super.onReceiveResult(resultCode, resultData);

                if (resultCode == Activity.RESULT_OK) {

                    String resultValue = resultData.getString("result");
                    Toast.makeText(ContactRequest.this, resultValue, Toast.LENGTH_SHORT).show();

                }
            }
        });

        Intent ContactRequestIntent = getIntent();

        mode = ContactRequestIntent.getStringExtra("mode");

        if(mode.equals("CR")){

            from = ContactRequestIntent.getStringExtra("fromAlias");
            fromIP = ContactRequestIntent.getStringExtra("IP");

            ContactRequestService.putExtra("mode", mode);
            ContactRequestService.putExtra("fromAlias", from);
            ContactRequestService.putExtra("IP", fromIP);


            displayContact.setText(from);


        } else if(mode.equals("Normal") || mode.equals("Normal1")) {

            name = ContactRequestIntent.getStringExtra("Name");
            key = ContactRequestIntent.getByteArrayExtra("ContactCert");

            ContactRequestService.putExtra("mode", mode);
            ContactRequestService.putExtra("Name", name);
            ContactRequestService.putExtra("Ckey", key);


            size = key.length;
            sizeS = Integer.toString(size);
            displayContact.setText(sizeS);


        } else if(mode.equals("HP")) {

            name = ContactRequestIntent.getStringExtra("fromAlias");
            myName = ContactRequestIntent.getStringExtra("toAlias");
            UDPendpoint1 = ContactRequestIntent.getStringExtra("endpoint1");
            UDPendpoint2 = ContactRequestIntent.getStringExtra("endpoint2");

            ContactRequestService.putExtra("mode", mode);
            ContactRequestService.putExtra("Name", name);
            ContactRequestService.putExtra("myName", myName);
            ContactRequestService.putExtra("endpoint1", UDPendpoint1);
            ContactRequestService.putExtra("endpoint2", UDPendpoint2);

            displayContact.setText(name);
        }



        buttonAccept.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                startService(ContactRequestService);

            }
        });

        buttonDeny.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                finish();

            }
        });

    }



}



