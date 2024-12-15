package com.iasonas.cryptovoip;


import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;



/**
 This class is used to take parameters from the user and start the service to add a contact locally. The user muust place an
 encoded certificate in pictures folder
 */

public class AddContact extends AppCompatActivity {

    public MyTestReceiver receiverForTest;

    Intent AddContactService;
    Button AddContact;
    Button Exit;
    EditText AddContactET;

    String ContactName;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_addcontact);

        Exit = findViewById(R.id.buttonExitAddContact);
        AddContact = findViewById(R.id.buttonAddContact);
        AddContactET = findViewById(R.id.edittextAddContact);


        setupServiceReceiver();

        AddContactService = new Intent(this, AddContactService.class);
        AddContactService.putExtra("receiver", receiverForTest);

        AddContact.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                ContactName = AddContactET.getText().toString();

                AddContactService.putExtra("alias", ContactName);

                startService(AddContactService);

            }
        });

        Exit.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                finish();
            }
        });
    }

    public void setupServiceReceiver() {
        receiverForTest = new MyTestReceiver(new Handler());

        receiverForTest.setReceiver(new MyTestReceiver.Receiver() {
            @Override
            public void onReceiveResult(int resultCode, Bundle resultData) {
                if (resultCode == RESULT_OK) {
                    String resultValue = resultData.getString("result");
                    Toast.makeText(AddContact.this, resultValue, Toast.LENGTH_SHORT).show();
                }
            }
        });
    }
}
