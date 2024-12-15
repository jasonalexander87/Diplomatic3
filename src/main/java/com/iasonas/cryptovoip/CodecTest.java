package com.iasonas.cryptovoip;

import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.AudioTrack;
import android.media.MediaCodec;
import android.media.MediaCodecList;
import android.media.MediaFormat;
import android.media.MediaRecorder;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.util.Arrays;

public class CodecTest implements Runnable {

    HandshakeResult Hresult;
    UdpEndpoints Uendps;
    String streamStatus;

    int sampleRate = 16000;
    int channelConfig = AudioFormat.CHANNEL_CONFIGURATION_MONO;
    int audioFormat = AudioFormat.ENCODING_PCM_16BIT;
    int minBufSize = AudioRecord.getMinBufferSize(sampleRate, channelConfig, audioFormat);

    public CodecTest(HandshakeResult HR, UdpEndpoints endP, String stream) {

        Hresult = HR;
        Uendps = endP;
        streamStatus = stream;
    }

    @Override
    public void run() {

        try {
            AudioRecord recorder;
            recorder = new AudioRecord(MediaRecorder.AudioSource.MIC, sampleRate, channelConfig, audioFormat, minBufSize * 10);

            MediaCodecList mcl = new MediaCodecList(MediaCodecList.REGULAR_CODECS);

            String audioformat = mcl.findEncoderForFormat(MediaFormat.createAudioFormat
                    (MediaFormat.KEY_PCM_ENCODING,16000,1));

            MediaCodec encoder = MediaCodec.createByCodecName(audioformat);
            encoder.configure(MediaFormat.createAudioFormat
                    (MediaFormat.MIMETYPE_AUDIO_AC3, 16000, 1), null, null, MediaCodec.CONFIGURE_FLAG_ENCODE);

            MediaFormat mediaformat = encoder.getOutputFormat();
            String audioformat2 = mcl.findDecoderForFormat(mediaformat);
            MediaCodec decoder = MediaCodec.createByCodecName(audioformat2);

            decoder.configure(MediaFormat.createAudioFormat
                    (MediaFormat.MIMETYPE_AUDIO_AC3,16000,1),null,null,0);

        }catch(java.io.IOException e) {}
    }
}
