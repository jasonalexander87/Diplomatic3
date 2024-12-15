package com.iasonas.cryptovoip;


import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.AudioTrack;
import android.media.MediaCodec;
import android.media.MediaCodecInfo;
import android.media.MediaFormat;
import android.media.MediaRecorder;
import android.util.Log;

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

public class MakeCallHPIn2 implements Runnable {

    Cipher cipher;
    long packetcounterIN;
    long packetcounterOUT;
    long threshold = 50000000;

    HandshakeResult Hresult;
    UdpEndpoints Uendps;
    String streamStatus;

    int sampleRate = 44100;
    private short audioFormat = AudioFormat.ENCODING_PCM_16BIT;
    private short channelConfig = AudioFormat.CHANNEL_IN_MONO;
    int minBufSize = AudioRecord.getMinBufferSize(sampleRate, channelConfig, audioFormat);


    ByteBuffer inputBuffer;
    ByteBuffer outputBuffer;


    MediaCodec.BufferInfo bufferInfo;
    int inputBufferId;
    int outputBufferId;

    byte[] confData = new byte[2];

    AudioTrack track;
    AudioRecord recorder;
    MediaCodec encoder;
    MediaCodec decoder;

    boolean isFirst = true;

    public MakeCallHPIn2(HandshakeResult HR, UdpEndpoints endP, String stream) {

        Hresult = HR;
        Uendps = endP;
        streamStatus = stream;
    }

    @Override
    public void run() {

        int len = 1024;
        byte[] buffer2 = new byte[len];
        DatagramPacket packet;

        byte[] data;

        ByteBuffer[] inputBuffers;
        ByteBuffer[] outputBuffers;

        ByteBuffer inputBuffer;
        ByteBuffer outputBuffer;

        MediaCodec.BufferInfo bufferInfo;
        int inputBufferIndex;
        int outputBufferIndex;
        byte[] outData;

        if(streamStatus.equals("RECEIVE")) {

            try {

                track = new AudioTrack(AudioManager.MODE_NORMAL, 44100, 1,
                        AudioFormat.ENCODING_PCM_16BIT, minBufSize, AudioTrack.MODE_STREAM);

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

                    byte[] dataDec = cipher.doFinal(data);
                    // Log.d("UDP Receiver",  data.length + " bytes received");

                    //===========
                    inputBuffers = decoder.getInputBuffers();
                    outputBuffers = decoder.getOutputBuffers();
                    inputBufferIndex = decoder.dequeueInputBuffer(-1);
                    if (inputBufferIndex >= 0)
                    {
                        inputBuffer = inputBuffers[inputBufferIndex];
                        inputBuffer.clear();

                        inputBuffer.put(dataDec);

                        decoder.queueInputBuffer(inputBufferIndex, 0, data.length, 0, 0);
                    }

                    bufferInfo = new MediaCodec.BufferInfo();
                    outputBufferIndex = decoder.dequeueOutputBuffer(bufferInfo, 0);

                    while (outputBufferIndex >= 0)
                    {
                        outputBuffer = outputBuffers[outputBufferIndex];

                        outputBuffer.position(bufferInfo.offset);
                        outputBuffer.limit(bufferInfo.offset + bufferInfo.size);

                        outData = new byte[bufferInfo.size];
                        outputBuffer.get(outData);

                        String dat = String.valueOf(outData.length);

                        Log.d("AudioDecoder", dat + " bytes decoded");


                        decoder.releaseOutputBuffer(outputBufferIndex, false);
                        outputBufferIndex = decoder.dequeueOutputBuffer(bufferInfo, 0);

                    }



                }

                track.stop();
                track.release();
                decoder.stop();
                decoder.release();

            } catch (java.io.IOException e) {
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }

        } else {


            AudioRecord recorder;
            recorder = new AudioRecord(MediaRecorder.AudioSource.MIC,
                    44100, 1, AudioFormat.ENCODING_PCM_16BIT, minBufSize );

            if(setEncoder(minBufSize)) {
                Log.d("ENCODER","SUCCESS");

            }
            setCipher(1,Hresult);

            byte[] buffer = new byte[minBufSize];

            encoder.start();
            recorder.startRecording();

            try {
                while (InboundCallActivityService.isRunning) {

                    recorder.read(buffer, 0, buffer.length);

                    inputBuffers = encoder.getInputBuffers();
                    outputBuffers = encoder.getOutputBuffers();
                    inputBufferIndex = encoder.dequeueInputBuffer(-1);
                    if (inputBufferIndex >= 0) {
                        inputBuffer = inputBuffers[inputBufferIndex];
                        inputBuffer.clear();

                        inputBuffer.put(buffer);

                        encoder.queueInputBuffer(inputBufferIndex, 0, buffer.length, 0, 0);
                    }

                    bufferInfo = new MediaCodec.BufferInfo();
                    outputBufferIndex = encoder.dequeueOutputBuffer(bufferInfo, 0);


                    while (outputBufferIndex >= 0) {
                        outputBuffer = outputBuffers[outputBufferIndex];

                        outputBuffer.position(bufferInfo.offset);
                        outputBuffer.limit(bufferInfo.offset + bufferInfo.size);

                        outData = new byte[bufferInfo.size];
                        outputBuffer.get(outData);

                        if (outData.length == 2) {
                            Log.d("buffer2---------", "CONFIGURATION");

                        }


                        Log.d("AudioEncoder", outData.length + " bytes encoded");
                        //-------------

                        byte[] encData = cipher.doFinal(outData);

                        packet = new DatagramPacket(encData, encData.length,
                                InetAddress.getByName("127.0.0.1"), 44444);
                        Uendps.getSock1().send(packet);
                        //------------

                        encoder.releaseOutputBuffer(outputBufferIndex, false);
                        outputBufferIndex = encoder.dequeueOutputBuffer(bufferInfo, 0);

                    }

                }
            }catch (java.net.UnknownHostException e) {} catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }

            recorder.stop();
            recorder.release();



        }
    }

    private boolean setEncoder(int bsize)
    {
        try {
            encoder = MediaCodec.createEncoderByType("audio/mp4a-latm");
            MediaFormat format = new MediaFormat();
            format.setString(MediaFormat.KEY_MIME, "audio/mp4a-latm");
            format.setInteger(MediaFormat.KEY_CHANNEL_COUNT, 1);
            format.setInteger(MediaFormat.KEY_SAMPLE_RATE, 44100);
            format.setInteger(MediaFormat.KEY_MAX_INPUT_SIZE,bsize);
            format.setInteger(MediaFormat.KEY_BIT_RATE, 64 * 1024);//AAC-HE 64kbps
            format.setInteger(MediaFormat.KEY_AAC_PROFILE, MediaCodecInfo.CodecProfileLevel.AACObjectHE);
            encoder.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE);
            return true;
        }catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    private boolean setDecoder(int bsize)
    {
        try {
            decoder = MediaCodec.createDecoderByType("audio/mp4a-latm");
            MediaFormat format = new MediaFormat();
            format.setString(MediaFormat.KEY_MIME, "audio/mp4a-latm");
            format.setInteger(MediaFormat.KEY_CHANNEL_COUNT, 1);
            format.setInteger(MediaFormat.KEY_SAMPLE_RATE, 44100);
            format.setInteger(MediaFormat.KEY_MAX_INPUT_SIZE,bsize);
            format.setInteger(MediaFormat.KEY_BIT_RATE, 64 * 1024);//AAC-HE 64kbps
            format.setInteger(MediaFormat.KEY_AAC_PROFILE, MediaCodecInfo.CodecProfileLevel.AACObjectHE);

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

    public byte[] encrypt2(byte[] data2enc) {

        try {

            return cipher.doFinal(data2enc);

        } catch(javax.crypto.BadPaddingException e) { return null; }
        catch(javax.crypto.IllegalBlockSizeException e) { return null; }
    }

    public byte[] encrypt(byte[] data2enc) {

        try {
            if(packetcounterOUT == Long.MAX_VALUE) { packetcounterOUT = 0; }
            packetcounterOUT++;

            byte[] encdata = cipher.doFinal(data2enc);
            ByteBuffer dbuf = ByteBuffer.allocate(8);
            dbuf.putLong(packetcounterOUT);
            byte[] sync = dbuf.array();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
            outputStream.write(sync);
            outputStream.write(encdata);

            return outputStream.toByteArray();

        } catch(javax.crypto.BadPaddingException e) { return null; }
        catch(javax.crypto.IllegalBlockSizeException e) { return null; }
        catch(java.io.IOException e) { return null; }
    }

    public byte[] decrypt2(byte[] data2dec) {

        try {
            return cipher.doFinal(data2dec);

        }catch (javax.crypto.BadPaddingException e) { return null; }
        catch (javax.crypto.IllegalBlockSizeException e) { return null;}

    }

    public byte[] decrypt(byte[] data2dec) {

        try {

            byte[] packetcount = Arrays.copyOfRange(data2dec, 0, 8);
            ByteBuffer wrapped = ByteBuffer.wrap(packetcount);
            long num = wrapped.getLong();
            byte[] data = Arrays.copyOfRange(data2dec, 8, data2dec.length);

            if(num < packetcounterIN) {
                if ((Long.MAX_VALUE - packetcounterIN + num) > threshold) {

                    return null;

                } else {

                    packetcounterIN = num;
                    return cipher.doFinal(data);

                }
            }
            if(num > packetcounterIN ) {
                if(num - packetcounterIN > threshold ) {
                    return null;
                }else {

                    packetcounterIN = num;
                    return cipher.doFinal(data);
                }

            }
            if(num == packetcounterIN) { return null; }

        }catch (javax.crypto.BadPaddingException e) { return null; }
        catch (javax.crypto.IllegalBlockSizeException e) { return null;}

        return null;
    }


    public void encode(byte[] data) {

        try {
            byte[] bufferAudio;
            byte[] bufferPack;

            inputBufferId = encoder.dequeueInputBuffer(-1);

            if (inputBufferId >= 0) {
                inputBuffer = encoder.getInputBuffer(inputBufferId);
                inputBuffer.clear();
                inputBuffer.put(data);

                encoder.queueInputBuffer(inputBufferId, 0, data.length, 0, 0);
                Log.d("Encoder", " IN");

            }

            if (data.length == 2) {
                Log.d("Encoder", " TWOBYTES");


            }

            bufferInfo = new MediaCodec.BufferInfo();
            outputBufferId = encoder.dequeueOutputBuffer(bufferInfo, 0);

            if ((bufferInfo.flags & MediaCodec.BUFFER_FLAG_CODEC_CONFIG) == MediaCodec.BUFFER_FLAG_CODEC_CONFIG) {
                Log.d("Encoder", " INFO=========================");

            }

            if (outputBufferId == -2) {
                Log.d("DECODEBUFID", " negative");
            }

            while (outputBufferId >= 0) {


                outputBuffer = encoder.getOutputBuffer(outputBufferId);

                outputBuffer.position(bufferInfo.offset);
                outputBuffer.limit(bufferInfo.offset + bufferInfo.size);

                bufferAudio = new byte[bufferInfo.size];
                outputBuffer.get(bufferAudio);

                if(bufferAudio.length == 2) {
                    Log.d("ENCODERout2", " 2byte");

                    confData = bufferAudio; }

                encoder.releaseOutputBuffer(outputBufferId, false);

                //bufferPack = concat(bufferAudio,confData);
                byte[] enData = encrypt2(bufferAudio);

                //String lineinfo[] = Uendps.getUDP1().split("x");
                //InetAddress destination = InetAddress.getByName(lineinfo[0].substring(1));
                //int port = Integer.parseInt(lineinfo[1]);
                //DatagramPacket packet = new DatagramPacket(enData, enData.length,destination, port);
                DatagramPacket packet = new DatagramPacket(enData, enData.length,
                        InetAddress.getByName("127.0.0.1"), 44444);
                Uendps.getSock1().send(packet);


                outputBufferId = encoder.dequeueOutputBuffer(bufferInfo, 0);

            }

        }catch(java.net.UnknownHostException e) {}
        catch(java.io.IOException e) {}
    }

    public void decode(byte[] data) {


        byte[] buffer3;
        byte[] deData = decrypt2(data);

        if(deData == null) {
            Log.d("NULL",   " NULL");

            return;
        }

        //byte[] configData = Arrays.copyOfRange(deData,0,2);
        //byte[] deDataSound = Arrays.copyOfRange(deData,2,deData.length);

        inputBufferId = decoder.dequeueInputBuffer(-1);

        if (inputBufferId >= 0) {
            inputBuffer = decoder.getInputBuffer(inputBufferId);
            inputBuffer.clear();

            inputBuffer.put(deData);

            decoder.queueInputBuffer(inputBufferId,0, data.length, 0, 0);
            Log.d("Decoder",   " IN");

        }

        if(data.length == 2) {
            Log.d("Decoder",   " TWOBYTES");


        }

        bufferInfo = new MediaCodec.BufferInfo();
        outputBufferId = decoder.dequeueOutputBuffer(bufferInfo,0);

        if ((bufferInfo.flags & MediaCodec.BUFFER_FLAG_CODEC_CONFIG) == MediaCodec.BUFFER_FLAG_CODEC_CONFIG) {
            Log.d("Decoder",   " INFO=========================");

        }

        if(outputBufferId == -2) { Log.d("DECODEBUFID",   " negative"); }

        while (outputBufferId >= 0) {


            outputBuffer = decoder.getOutputBuffer(outputBufferId);

            outputBuffer.position(bufferInfo.offset);
            outputBuffer.limit(bufferInfo.offset + bufferInfo.size);

            buffer3 = new byte[bufferInfo.size];
            outputBuffer.get(buffer3);

            decoder.releaseOutputBuffer(outputBufferId, false);

            outputBufferId = decoder.dequeueOutputBuffer(bufferInfo, 0);
            Log.d("Decoder", " OUT");

            track.write(buffer3, 0, buffer3.length);


        }

    }

    public byte[] concat(byte[] message2con, byte[] confD) {

        try{

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(confD);
            outputStream.write(message2con);
            return outputStream.toByteArray();

        }catch (java.io.IOException e) { return null; }
    }
}

