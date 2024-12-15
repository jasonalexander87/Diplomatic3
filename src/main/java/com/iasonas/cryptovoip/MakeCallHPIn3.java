package com.iasonas.cryptovoip;


import android.media.AudioAttributes;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.AudioTrack;
import android.media.MediaCodec;
import android.media.MediaCodecInfo;
import android.media.MediaFormat;
import android.media.MediaRecorder;
import android.util.Log;

import androidx.core.content.res.TypedArrayUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;

public class MakeCallHPIn3 implements Runnable {

    long packetcounterIN = 0;
    long packetcounterOUT = 0;
    int threshold = 50000;

    HandshakeResult Hresult;
    UdpEndpoints Uendps;
    String streamStatus;


    int minBufSize = AudioRecord.getMinBufferSize(44100, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT);

    ByteBuffer inputBuffer;
    ByteBuffer outputBuffer;

    ByteBuffer inputBuffer2;
    ByteBuffer outputBuffer2;

    MediaCodec.BufferInfo bufferInfo;
    MediaCodec.BufferInfo bufferInfo2;
    int inputBufferId;
    int outputBufferId;
    int inputBufferId2;
    int outputBufferId2;


    byte[] confData = new byte[2];

    Cipher cipher;
    Cipher cipher2;
    AudioTrack track;
    AudioRecord recorder;
    MediaCodec encoder;
    MediaCodec decoder;

    int len = 1024;
    byte[] buffer2 = new byte[len];
    DatagramPacket packet;

    byte[] data;

    boolean isFirst = true;
    int counter=0;

    public MakeCallHPIn3(HandshakeResult HR, UdpEndpoints endP, String stream) {

        Hresult = HR;
        Uendps = endP;
        streamStatus = stream;
    }

    @Override
    public void run() {

        if(streamStatus.equals("RECEIVE")) {

            try {

                track = new AudioTrack.Builder()
                        .setAudioAttributes(new AudioAttributes.Builder()
                                .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                                .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                                .build())
                        .setAudioFormat(new AudioFormat.Builder()
                                .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                                .setSampleRate(44100)
                                .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                                .build())
                        .setBufferSizeInBytes(minBufSize)
                        .build();

                setCipher(0,Hresult);

                if(setDecoder(minBufSize)) {
                    Log.d("DECODER","SUCCESS");

                }
                decoder.start();
                track.play();

                byte[] buffer = new byte[minBufSize];
                packet = new DatagramPacket(buffer, buffer.length);

                while (InboundCallActivityService.isRunning) {

                    Uendps.getSock1().receive(packet);

                    data = new byte[packet.getLength()];
                    System.arraycopy(packet.getData(), packet.getOffset(), data, 0, packet.getLength());

                    decode(data);

                }

                track.stop();
                track.release();
                decoder.stop();
                decoder.release();

            } catch (java.io.IOException e) {
            }

        } else if(streamStatus.equals("SEND")) {


            recorder = new AudioRecord.Builder()
                    .setAudioSource(MediaRecorder.AudioSource.VOICE_COMMUNICATION)
                    .setAudioFormat(new AudioFormat.Builder()
                            .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                            .setSampleRate(44100)
                            .setChannelMask(AudioFormat.CHANNEL_IN_MONO)
                            .build())
                    .setBufferSizeInBytes(minBufSize)
                    .build();

            if(setEncoder(minBufSize)) {
                Log.d("ENCODER","SUCCESS");

            }
            setCipher(1,Hresult);

            byte[] buffer = new byte[minBufSize];

            encoder.start();
            recorder.startRecording();

            while (InboundCallActivityService.isRunning) {

                recorder.read(buffer, 0, buffer.length);
                encode(buffer);

            }

            recorder.stop();
            recorder.release();

        }
    }

    private boolean setEncoder(int rate)
    {
        try {
            encoder = MediaCodec.createEncoderByType("audio/mp4a-latm");
            MediaFormat format = new MediaFormat();
            format.setString(MediaFormat.KEY_MIME, "audio/mp4a-latm");
            format.setInteger(MediaFormat.KEY_PCM_ENCODING, AudioFormat.ENCODING_PCM_16BIT);
            format.setInteger(MediaFormat.KEY_CHANNEL_COUNT, 1);
            format.setInteger(MediaFormat.KEY_SAMPLE_RATE, 44100);
            format.setInteger(MediaFormat.KEY_MAX_INPUT_SIZE,minBufSize);
            format.setInteger(MediaFormat.KEY_BIT_RATE, 64 * 1024);//AAC-HE 64kbps
            format.setInteger(MediaFormat.KEY_AAC_PROFILE, MediaCodecInfo.CodecProfileLevel.AACObjectMain);
            encoder.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE);
            return true;
        }catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    private boolean setDecoder(int rate)
    {
        try {
            decoder = MediaCodec.createDecoderByType("audio/mp4a-latm");
            MediaFormat format = new MediaFormat();
            format.setString(MediaFormat.KEY_MIME, "audio/mp4a-latm");
            format.setInteger(MediaFormat.KEY_PCM_ENCODING, AudioFormat.ENCODING_PCM_16BIT);
            format.setInteger(MediaFormat.KEY_CHANNEL_COUNT, 1);
            format.setInteger(MediaFormat.KEY_SAMPLE_RATE, 44100);
            format.setInteger(MediaFormat.KEY_MAX_INPUT_SIZE,minBufSize);
            format.setInteger(MediaFormat.KEY_BIT_RATE, 64 * 1024);//AAC-HE 64kbps
            //format.setInteger(MediaFormat.KEY_AAC_PROFILE, MediaCodecInfo.CodecProfileLevel.AACObjectLC);

            decoder.configure(format, null, null, 0);

            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }


    public boolean setCipher(int mode,HandshakeResult HR) {

        try{
            if(mode == 1) {
                cipher = Cipher.getInstance("AES/CTR/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, HR.getKey(), HR.getIV());
            } else {
                cipher = Cipher.getInstance("AES/CTR/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, HR.getKey(), HR.getIV());
            }

            return true;

        }catch (java.security.NoSuchAlgorithmException e) { return false; }
        catch (javax.crypto.NoSuchPaddingException e) { return false; }
        catch (java.security.InvalidAlgorithmParameterException e) { return false; }
        catch (java.security.InvalidKeyException e) { return false; }

    }



    public byte[] encrypt(byte[] data2enc) {

        if(packetcounterOUT == Long.MAX_VALUE) {

            packetcounterOUT = data2enc.length;

        } else if(packetcounterOUT > Long.MAX_VALUE - data2enc.length) {

            packetcounterOUT = Long.MAX_VALUE - packetcounterOUT;
            packetcounterOUT = data2enc.length - packetcounterOUT;

        } else { packetcounterOUT = packetcounterOUT + data2enc.length; }


        byte[] encdata = cipher.update(data2enc);

        byte[] count = ByteBuffer.allocate(8).putLong(packetcounterOUT).array();
        //Log.d("ENCODED=ENCRYPTED=DATA", packetcounterOUT+"//"+encdata.length+"///"+byteArrayToHex(encdata));


        return concat(encdata,confData, count);

    }



    public byte[] decrypt(byte[] data2dec) {

        long num = ByteBuffer.wrap(Arrays.copyOfRange(data2dec,0,8)).getLong();


        //Log.d("=====DECRYPTCOUNTER", num+"///");


        //return cipher.update(data2dec, 10, data2dec.length-10);

        if(num < packetcounterIN ) {
            if ((Long.MAX_VALUE - packetcounterIN + num) > threshold) {

                Log.d("DECRYPT===1","THRESHHOLD");

                return null;

            } else if((Long.MAX_VALUE - packetcounterIN + num) < threshold) {

                Log.d("DECRYPT===2","INBOUNDS");

                long distance = (Long.MAX_VALUE - packetcounterIN + num - data2dec.length + 10);

                if(distance < Integer.MAX_VALUE) {

                    int Idistance = (int) distance;
                    byte[] trash = new byte[Idistance];
                    cipher.update(trash);
                    packetcounterIN = num;

                    return cipher.update(data2dec, 10, data2dec.length-10);

                } else { return null;}

            } else { return null; }


        } else if(num > packetcounterIN ) {
            if(num - packetcounterIN  > threshold ) {

                Log.d("DECRYPT","3THREE");

                return null;
            }else if(num - packetcounterIN  < threshold) {

                if(num == packetcounterIN + data2dec.length -10) {

                    //Log.d("DECRYPT","EXPECTED");

                    packetcounterIN = num;
                    return cipher.update(data2dec, 10, data2dec.length-10);

                } else if(num > packetcounterIN + data2dec.length -10) {

                    long distance = num-packetcounterIN - data2dec.length +10;

                    if(distance < Integer.MAX_VALUE) {

                        int Idistance = (int) distance;
                        byte[] trash = new byte[Idistance];
                        cipher.update(trash);
                        packetcounterIN = num;
                        Log.d("DECRYPT","EXPECTED");

                        return cipher.update(data2dec, 10, data2dec.length-10);

                    } else { return null;}
                } else { return null; }

            }

        } else { return null;}

        return null;

    }


    public void encode(byte[] data2E) {

        try {

            counter++;

            inputBufferId = encoder.dequeueInputBuffer(-1);

            if (inputBufferId >= 0) {
                inputBuffer = encoder.getInputBuffer(inputBufferId);
                inputBuffer.clear();
                inputBuffer.put(data2E);

                encoder.queueInputBuffer(inputBufferId,0, data2E.length, 0, 0);
                //Log.d("Encoder",   " IN");

            }

            bufferInfo = new MediaCodec.BufferInfo();

            outputBufferId = encoder.dequeueOutputBuffer(bufferInfo,0);

            if ((bufferInfo.flags & MediaCodec.BUFFER_FLAG_CODEC_CONFIG) == MediaCodec.BUFFER_FLAG_CODEC_CONFIG) {
                Log.d("Encoder",   " INFO=========================");

            }

            if(outputBufferId == -2) { Log.d("ENCODEBUFID",   " negative"); }

            while (outputBufferId >= 0) {


                outputBuffer = encoder.getOutputBuffer(outputBufferId);

                outputBuffer.position(bufferInfo.offset);
                outputBuffer.limit(bufferInfo.offset + bufferInfo.size);

                buffer2 = new byte[bufferInfo.size];
                outputBuffer.get(buffer2);

                encoder.releaseOutputBuffer(outputBufferId, false);
                //Log.d("Encoder", " OUT");

                if(buffer2.length == 2) {
                    Log.d("ENCODER=====", " CONFBYTES===");
                    confData = Arrays.copyOf(buffer2, buffer2.length);

                    //Log.d("TWOBYTES=====", byteArrayToHex(buffer2));
                    //Log.d("TWOBYTES=====", byteArrayToHex(confData));


                }

                byte[] bufferE = encrypt(buffer2);


                packet = new DatagramPacket(bufferE, bufferE.length,
                        InetAddress.getByName("127.0.0.1"), 44444);
                if(counter > 10) {
                    Uendps.getSock1().send(packet);
                } else { Log.d("====ENCRYPT====","SKIIPPPING==============="); }
                outputBufferId = encoder.dequeueOutputBuffer(bufferInfo, 0);


            }


        }catch(java.net.UnknownHostException e) {}
        catch(java.io.IOException e) {}
    }

    public void decode(byte[] Indata) {

        byte[] buffer3;

        byte[] dataDe = decrypt(Indata);

        if(isFirst) {
            dataDe = Arrays.copyOfRange(Indata,8,10);
            isFirst = false;
            Log.d("DECODE=====", "FIRST==========");

        }

        inputBufferId2 = decoder.dequeueInputBuffer(-1);

        if (inputBufferId2 >= 0) {
            inputBuffer2 = decoder.getInputBuffer(inputBufferId2);
            inputBuffer2.clear();
            inputBuffer2.put(dataDe);

            decoder.queueInputBuffer(inputBufferId2,0, dataDe.length, 0, 0);
            //Log.d("Decoder",   " IN");

        }

        if(data.length == 2) {
            //Log.d("Decoder",   " TWOBYTES");


        }

        bufferInfo2 = new MediaCodec.BufferInfo();
        outputBufferId2 = decoder.dequeueOutputBuffer(bufferInfo2,0);

        if ((bufferInfo2.flags & MediaCodec.BUFFER_FLAG_CODEC_CONFIG) == MediaCodec.BUFFER_FLAG_CODEC_CONFIG) {
            Log.d("Decoder",   " INFO=========================");

        }

        if(outputBufferId2 == -2) { Log.d("DECODEBUFID",   " negative"); }

        while (outputBufferId2 >= 0) {


            outputBuffer2 = decoder.getOutputBuffer(outputBufferId2);

            outputBuffer2.position(bufferInfo2.offset);
            outputBuffer2.limit(bufferInfo2.offset + bufferInfo2.size);

            buffer3 = new byte[bufferInfo2.size];
            outputBuffer2.get(buffer3);

            decoder.releaseOutputBuffer(outputBufferId2, false);

            outputBufferId2 = decoder.dequeueOutputBuffer(bufferInfo2, 0);
            //Log.d("Decoder", " OUT");

            track.write(buffer3, 0, buffer3.length);



        }

    }



    public byte[] concat(byte[] message2con, byte[] confD, byte[] count) {

        try{

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(count);
            outputStream.write(confD);
            outputStream.write(message2con);
            return outputStream.toByteArray();

        }catch (java.io.IOException e) { return null; }
    }

    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }
}


