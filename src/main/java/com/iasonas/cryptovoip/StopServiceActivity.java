package com.iasonas.cryptovoip;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import android.Manifest;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.ResultReceiver;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

public class StopServiceActivity extends AppCompatActivity {

    Button btnStartTracking;
    Button btnStopTracking;
    TextView txtStatus;


    public Service2 service2;
    public boolean mTracking = false;
    private static final int REQUEST_CAMERA_PERMISSION = 200;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_stopservice);


        btnStopTracking = (Button)findViewById(R.id.btn_stop_service);


        btnStopTracking.setOnClickListener(new View.OnClickListener() {
            public void onClick(View _view) {

                service2.stopService();
                finish();

            }
        });

        final Intent intent = new Intent(this.getApplication(), Service2.class);


        this.getApplication().bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE);

    }

    private ServiceConnection serviceConnection = new ServiceConnection() {
        public void onServiceConnected(ComponentName className, IBinder service) {
            String name = className.getClassName();
            if (name.endsWith("Service2")) {
                service2 = ((Service2.ServiceBinder) service).getService();
            }
        }

        public void onServiceDisconnected(ComponentName className) {
            if (className.getClassName().equals("Service2")) {
                service2 = null;
            }
        }
    };



}
