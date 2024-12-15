package com.iasonas.cryptovoip;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

public class MainActivity extends AppCompatActivity {

    Intent Server;
    Intent AddContact;
    Intent RemoveContact;
    Intent MakeCall;
    Intent WebOfTrust;
    Intent InitializeA;
    Intent AddRemonteContact;

    Button startService;
    Button stopService;
    Button addContact;
    Button removeContact;
    Button makeCall;
    Button webOfTrust;
    Button Initialize;
    Button AddRemoteContact;
    private static final int REQUEST_PERMISSION = 200;



    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        if((ActivityCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED))

        {
            ActivityCompat.requestPermissions(this,new String[]{

                    Manifest.permission.RECORD_AUDIO, Manifest.permission.WRITE_EXTERNAL_STORAGE, Manifest.permission.READ_EXTERNAL_STORAGE

            },REQUEST_PERMISSION);

        }


        Server = new Intent(this, ServerService.class);
        AddContact = new Intent(this, AddContact.class);
        //RemoveContact = new Intent(this, RemoveContact.class);
        MakeCall = new Intent(this, OutboundCallActivity.class);
        //WebOfTrust = new Intent(this, WebOfTrust.class);
        InitializeA = new Intent(this, Initialize.class);
        AddRemonteContact = new Intent(this, AddRemoteContact.class);

        startService = (Button)findViewById(R.id.buttonStartServiceMain);
        stopService = (Button)findViewById(R.id.buttonStopServiceMain);
        addContact = (Button)findViewById(R.id.buttonAddContactMain);
        removeContact = (Button)findViewById(R.id.buttonRemoveContactMain);
        makeCall = (Button)findViewById(R.id.buttonMakeCallMain);
        webOfTrust = (Button)findViewById(R.id.buttonWebOfTrustMain);
        Initialize = (Button) findViewById(R.id.buttonInitialize);
        AddRemoteContact = (Button) findViewById(R.id.buttonAddRemote);

        startService.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                startService(Server);
                startService.setEnabled(false);
                stopService.setEnabled(true);
                finish();

            }
        });

        stopService.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                stopService(Server);
                startService.setEnabled(true);
                stopService.setEnabled(false);
                finish();

            }
        });

        Initialize.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                startActivity(InitializeA);
                finish();

            }
        });


        AddRemoteContact.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                startActivity(AddRemonteContact);
                finish();

            }
        });

        addContact.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                startActivity(AddContact);
                finish();

            }
        });

        removeContact.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                startActivity(RemoveContact);
                finish();

            }
        });

        makeCall.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                startActivity(MakeCall);
                finish();

            }
        });

        webOfTrust.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                startActivity(WebOfTrust);
                finish();

            }
        });

    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {

        if(requestCode == REQUEST_PERMISSION)

        {

            if(grantResults[0] != PackageManager.PERMISSION_GRANTED )

            {

                Toast.makeText(this, "PERMISSIONS REQUIRED", Toast.LENGTH_SHORT).show();

                finish();

            }

        }

    }
}

