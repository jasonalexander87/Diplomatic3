package com.iasonas.cryptovoip;

import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.AudioTrack;
import android.media.MediaRecorder;

import java.net.DatagramPacket;
import java.net.InetAddress;

public class MakeCallHPOut implements Runnable {

    HandshakeResult Hresult;
    UdpEndpoints Uendps;
    String streamStatus;

    int sampleRate = 16000;
    int channelConfig = AudioFormat.CHANNEL_CONFIGURATION_MONO;
    int audioFormat = AudioFormat.ENCODING_PCM_16BIT;
    int minBufSize = AudioRecord.getMinBufferSize(sampleRate, channelConfig, audioFormat);

    public MakeCallHPOut(HandshakeResult HR, UdpEndpoints endP, String stream) {

        Hresult = HR;
        Uendps = endP;
        streamStatus = stream;
    }

    @Override
    public void run() {

        if(streamStatus.equals("RECEIVE")) {

            try {

                AudioTrack track;
                track = new AudioTrack(AudioManager.MODE_NORMAL, 16000, AudioFormat.CHANNEL_CONFIGURATION_MONO,
                        AudioFormat.ENCODING_PCM_16BIT, minBufSize, AudioTrack.MODE_STREAM);

                track.play();

                byte[] buffer = new byte[minBufSize];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

                while (OutboundCallActivityService.isRunning) {

                    Uendps.getSock1().receive(packet);
                    String message = new String(buffer);
                    if(message.equals("Hello")) { continue; }
                    track.write(buffer, 0, buffer.length);
                    track.flush();

                }

                track.stop();
                track.release();

            } catch (java.io.IOException e) {
            }

        } else {

            try{

                AudioRecord recorder;
                recorder = new AudioRecord(MediaRecorder.AudioSource.MIC, sampleRate, channelConfig, audioFormat, minBufSize * 10);

                byte[] buffer = new byte[minBufSize];
                String lineinfo[] = Uendps.getUDP2().split("x");
                InetAddress destination = null;
                destination = InetAddress.getByName(lineinfo[0].substring(1));
                int port1 = Integer.parseInt(lineinfo[1]);
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length, destination, port1);

                recorder.startRecording();

                while(OutboundCallActivityService.isRunning) {

                    recorder.read(buffer, 0 , buffer.length);
                    Uendps.getSock2().send(packet);

                }

                recorder.stop();
                recorder.release();


            } catch (java.net.UnknownHostException e ) {}
            catch (java.io.IOException e) {}
        }
    }
}
