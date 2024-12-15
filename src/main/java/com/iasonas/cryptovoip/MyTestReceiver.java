package com.iasonas.cryptovoip;

import android.os.Bundle;
import android.os.Handler;
import android.os.ResultReceiver;

/**
 This class is used to create a Result receiver to pass info from intent service to Activity and vice versa
 */

public class MyTestReceiver extends ResultReceiver {
    private Receiver receiver;

    public MyTestReceiver(Handler handler) {
        super(handler);
    }

    public void setReceiver(Receiver receiver) {
        this.receiver = receiver;
    }

    public interface Receiver {
        void onReceiveResult(int resultCode, Bundle resultData);
    }

    @Override
    protected void onReceiveResult(int resultCode, Bundle resultData) {
        if (receiver != null) {
            receiver.onReceiveResult(resultCode, resultData);
        }
    }
}