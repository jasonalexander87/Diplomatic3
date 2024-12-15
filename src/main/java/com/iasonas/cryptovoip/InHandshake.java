package com.iasonas.cryptovoip;

import android.os.Environment;
import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class InHandshake {

    UdpEndpoints endPoints;
    public String IP;
    public String Cname;
    public String mode;
    String result;

    ObjectInputStream input;
    ObjectOutputStream output;
    Socket socket;


    public InHandshake(String Ip, String Contact, String m, UdpEndpoints endP)
    {
        IP = Ip;
        Cname = Contact;
        mode = m;
        endPoints = endP;
    }



    public byte[] concat(byte[] Pkey, byte[] sig) {

        try{

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(Pkey);
            outputStream.write(sig);
            return outputStream.toByteArray();

        }catch (java.io.IOException e) { return null; }
    }

    public void sendHP(byte[] data2send, DatagramSocket so) {

        boolean flag = false;
        int counter = 0;
        String lineinfo[] = endPoints.getUDP1().split("x");
        InetAddress destination = null;
        int port1 = Integer.parseInt(lineinfo[1]);

        try {
            destination = InetAddress.getByName(lineinfo[0].substring(1));
        }catch(java.net.UnknownHostException e) { }

        DatagramPacket Packet = new DatagramPacket(data2send, data2send.length, destination, port1);
        byte[] ackM = new byte[512];
        DatagramPacket ack = new DatagramPacket(ackM, ackM.length);

        try {
            so.setSoTimeout(300);

        }catch(java.net.SocketException e) {}

        while(counter < 10 && !flag) {

            try {
                so.send(Packet);

                while(ack.getLength() != 3) {
                    try{

                        so.receive(ack);
                            Log.d("RECEIVE","INSIDELOOP"+ack.getLength());

                    } catch(java.net.SocketTimeoutException e) { break;}
                }

                counter++;

                if(ack.getLength() == 3) {
                    Log.d("RECEIVE","OUTSIDELOOP"+ack.getLength());
                    flag = true;

                }




            } catch (java.io.IOException e) { return;}

        }

    }

    public byte[] receiveHP(DatagramSocket so) {

        boolean flag = false;
        String lineinfo[] = endPoints.getUDP1().split("x");
        InetAddress destination = null;
        int port1 = Integer.parseInt(lineinfo[1]);


        try {
            destination = InetAddress.getByName(lineinfo[0].substring(1));
        }catch(java.net.UnknownHostException e) { return "FAILED1".getBytes(); }


        byte[] buf = new byte[1024];
        DatagramPacket Packet = new DatagramPacket(buf, buf.length);
        byte[] ackM = "ACK".getBytes();
        DatagramPacket ack = new DatagramPacket(ackM, ackM.length, destination, port1);

        try {
            so.setSoTimeout(5000);

        }catch(java.net.SocketException e) {}

        int counter = 0;


        while(counter < 3) {

            try {
                so.receive(Packet);
                if (Packet.getLength() == 430) {
                    Log.d("RECEIVE","RECEIVE");

                    so.send(ack);

                    try {
                        Thread.sleep(200);
                    } catch (java.lang.InterruptedException e) {
                    }
                    so.send(ack);
                    return buf;
                } else {  Log.d("RECEIVE","NOTEXPECTED"); }

            }catch (java.net.SocketTimeoutException e) {

                counter++;
                continue;
            }
            catch (java.io.IOException e) { return  null;}
        }

        return null;
    }


    public HandshakeResult doHandshakeHP() {

        LoadKeyReturn keys;
        LoadKeyReturn Ephkeys;
        byte[] EpeerPubEnc;
        PublicKey Epeerpublic;
        byte[] signature;
        byte[] signatureReceived;
        boolean SignatureResult = true;
        byte[] secret;
        SecretKeySpec secretKeyGenerated;
        byte[] IV;
        byte[] salt = new byte[256];
        byte[] dataSend;
        byte[] dataReceive;


        keys = loadMyKeyPair(Cname);

        //bhma2 paragwgh ephemeral key pair
        Ephkeys = loadmyEphemeralKeyPair();

        signature = signEphemeralPublic(keys.getPrivate(), Ephkeys.getPublic());

        dataSend = concat(Ephkeys.getPublic().getEncoded(),signature);
        Log.d("BREAKPOINT","SEND "+Ephkeys.getPublic().getEncoded().length);
        Log.d("BREAKPOINT","SEND "+signature.length);
        Log.d("BREAKPOINT","SEND "+dataSend.length);


        sendHP(dataSend, endPoints.getSock1());
        dataReceive = receiveHP(endPoints.getSock1());


        EpeerPubEnc = Arrays.copyOfRange(dataReceive,0,158);

        signatureReceived = Arrays.copyOfRange(dataReceive,158,414);

        IV = Arrays.copyOfRange(dataReceive,414,430);
        SignatureResult = checkSignature(signatureReceived, keys.getPublic(), EpeerPubEnc);
        if(SignatureResult) { Log.d("SIGNATURE","SUCCESS==================");
        }
        Epeerpublic = PublicDecode(EpeerPubEnc);

        secret = generateSecret(Ephkeys.getPrivate(), Epeerpublic);
        byte[] hashsec = hashsecret(secret);

        Log.d("SECRET",hashsec.length + "//"+byteArrayToHex(hashsec));

        Log.d("IV",IV.length + "//"+byteArrayToHex(IV));


        secretKeyGenerated = generateSecretKey(secret);


        IvParameterSpec iv = new IvParameterSpec(IV);



        String res = "SUCCESS";
        HandshakeResult HR = new HandshakeResult();
        HR.setstatus(res);
        HR.setKey(secretKeyGenerated);
        HR.setIV(iv);
        return HR;


    }


    public HandshakeResult doHandshakeNormal() {

        LoadKeyReturn keys;
        LoadKeyReturn Ephkeys;
        byte[] EpeerPubEnc;
        PublicKey Epeerpublic;
        byte[] signature;
        byte[] signatureReceived;
        boolean SignatureResult = true;
        byte[] secret;
        SecretKeySpec secretKeyGenerated;
        byte[] IV;
        byte[] salt = new byte[256];

        try {

            socket = new Socket();
            InetSocketAddress socketaddr = new InetSocketAddress("192.168.1.4", 4444);
            while (!socket.isConnected()) {
                socket.connect(socketaddr, 0);
            }

            output = new ObjectOutputStream(socket.getOutputStream());
            input = new ObjectInputStream(socket.getInputStream());

            keys = loadMyKeyPair(Cname);

            //bhma2 paragwgh ephemeral key pair
            Ephkeys = loadmyEphemeralKeyPair();


            EpeerPubEnc = (byte[]) input.readObject();
            output.writeObject(Ephkeys.getPublic().getEncoded());

            signature = signEphemeralPublic(keys.getPrivate(), Ephkeys.getPublic());

            signatureReceived = (byte[]) input.readObject();
            output.writeObject(signature);

            SignatureResult = checkSignature(signatureReceived, keys.getPublic(), EpeerPubEnc);

            Epeerpublic = PublicDecode(EpeerPubEnc);

            secret = generateSecret(Ephkeys.getPrivate(), Epeerpublic);

           // byte[] hashsec = hashsecret(secret);


            secretKeyGenerated = generateSecretKey(secret);


            IV = (byte[]) input.readObject();
            IvParameterSpec iv = new IvParameterSpec(IV);


            /*
            if(IV == null) {

                HandshakeResult HR = new HandshakeResult();
                HR.setstatus("IVNULL");
                return HR;
            }

            byte[] mess1 = enc(secretKeyGenerated, IV);

            if(mess1 == null) {

                HandshakeResult HR = new HandshakeResult();
                HR.setstatus(result);
                return HR;
            }

            byte[] mess2 = (byte[]) input.readObject();
            output.writeObject(mess1);

            byte[] dmess = dec(mess2, secretKeyGenerated, IV);
            byte[] test = "HELLO".getBytes();

*/

            String res = "SUCCESS";
            HandshakeResult HR = new HandshakeResult();
            HR.setstatus(res);
            HR.setKey(secretKeyGenerated);
            HR.setIV(iv);
            return HR;




        } catch (java.io.IOException e) {

            HandshakeResult HR = new HandshakeResult();

            HR.setstatus("IOEXCEPTION");
            return HR;
        }
        catch (java.lang.ClassNotFoundException e) {

            HandshakeResult HR = new HandshakeResult();

            HR.setstatus("CLASSNOTFOUND");
            return HR;
        }
    }

    public byte[] dec(byte[] cipherM, SecretKeySpec key, byte[] initV) {

        try{

            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(initV));

            byte[] res = cipher.doFinal(cipherM);

            return res;

        }catch (java.security.NoSuchAlgorithmException e) { return null; }
        catch (java.security.InvalidAlgorithmParameterException e) { return null; }
        catch (java.security.InvalidKeyException e) { return null; }
        catch (javax.crypto.NoSuchPaddingException e) { return null; }
        catch (javax.crypto.BadPaddingException e) { return null; }
        catch (javax.crypto.IllegalBlockSizeException e) { return null; }

    }

    public byte[] enc(SecretKeySpec key, byte[] initV) {

        try {

            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(initV));

            byte[] res = cipher.doFinal("HELLO".getBytes("UTF-8"));

            return res;

        }catch (java.security.NoSuchAlgorithmException e) { result = "1"; return null; }
        catch (java.security.InvalidAlgorithmParameterException e) { result = "2"; return null; }
        catch (java.security.InvalidKeyException e) { result = "3"; return null; }
        catch (javax.crypto.NoSuchPaddingException e) { result = "4"; return null; }
        catch (javax.crypto.BadPaddingException e) { result = "5"; return null; }
        catch (javax.crypto.IllegalBlockSizeException e) { result = "6"; return null; }
        catch (java.io.UnsupportedEncodingException e) { result = "7"; return null; }


    }

    public SecretKey generateSecretKeyPB(byte[] sec) {

        try {
            String pass = new String(sec, "UTF-8");
            char[] pass2 = pass.toCharArray();

            int count = 1000;
            byte[] salt = "12345".getBytes();

            PBEKeySpec pbeKeySpec = new PBEKeySpec(pass2, salt, count, 256);
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEwithHmacSHA256AndAES_256");
            SecretKey result = keyFac.generateSecret(pbeKeySpec);

            return result;

        }catch (java.io.UnsupportedEncodingException e) {  return null; }
         catch (java.security.NoSuchAlgorithmException e) { return null; }
         catch (java.security.spec.InvalidKeySpecException e) { return null; }

    }


    public SecretKeySpec generateSecretKey(byte[] secret) {

        SecretKeySpec result = new SecretKeySpec(secret, "AES");

        return result;

    }

    public byte[] hashsecret(byte[] secret) {

        try {
            byte[] key;

            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update(secret);
            key = hash.digest();


            return key;

        }catch(java.security.NoSuchAlgorithmException e) { return null; }
    }

    ////////////////////////////////LoadMyKeyPair////////////////////////////////////////////////////////
    public LoadKeyReturn loadMyKeyPair(String contact) {


        try {

            PrivateKey myPrivateKey;
            PublicKey peerPublicKey;
            LoadKeyReturn keys;

            File file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES), "keystore.p12");
            KeyStore keyStore = KeyStore.getInstance("pkcs12");
            FileInputStream instream = new FileInputStream(file);
            keyStore.load(instream, "password".toCharArray());
            instream.close();
            KeyStore.ProtectionParameter protparam = new KeyStore.PasswordProtection("password".toCharArray());
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("me", protparam);
            myPrivateKey = privateKeyEntry.getPrivateKey();


            X509Certificate peerCert = (X509Certificate) keyStore.getCertificate(contact);
            peerPublicKey = peerCert.getPublicKey();

            keys = new LoadKeyReturn();
            keys.setPublic(peerPublicKey);
            keys.setPrivate(myPrivateKey);
            keys.setResult("SUCCESS");

            return keys;

        }catch(java.io.IOException e) { result = "IOException"; }
        catch(java.security.NoSuchAlgorithmException e) { result = "NoSuchAlgorithmException"; }
        catch(java.security.cert.CertificateException e) { result = "CertException"; }
        catch(java.security.KeyStoreException e) { result = "KeystoreException"; }
        catch(java.security.UnrecoverableEntryException e) { result = "UnrecoverableEntryException";  }


        LoadKeyReturn keys = null;
        keys.setResult("FAILED");


        return keys;
    }

    ///////////////////load ephemeral key pair/////////////////////////////////////////////////////////////
    public LoadKeyReturn loadmyEphemeralKeyPair() {

        try {

            PrivateKey myEphemeralPrivateKey;
            PublicKey myEphemeralPublicKey;
            LoadKeyReturn keys;

            KeyPairGenerator myEphemeralKeyPairGen = KeyPairGenerator.getInstance("EC");
            myEphemeralKeyPairGen.initialize(521);
            KeyPair myEphemeralKeyPair = myEphemeralKeyPairGen.generateKeyPair();
            myEphemeralPrivateKey = myEphemeralKeyPair.getPrivate();
            myEphemeralPublicKey = myEphemeralKeyPair.getPublic();

            keys = new LoadKeyReturn();
            keys.setPrivate(myEphemeralPrivateKey);
            keys.setPublic(myEphemeralPublicKey);

            keys.setResult("SUCCESS");

            return keys;

        }catch(java.security.NoSuchAlgorithmException e) { result = "FAILED_loadMyEphemeral_NoSuchAlgorithmException"; }

        LoadKeyReturn keys = new LoadKeyReturn();
        keys.setResult("FAILED");
        return keys;
    }



    ///////////Sing ephemeral public//////////////////////////////////////////////
    public byte[] signEphemeralPublic(PrivateKey myPrivate, PublicKey myEPublic) {
        try {
            byte[] resultKey;

            Signature rsaSignature = Signature.getInstance("SHA256withRSA");
            rsaSignature.initSign(myPrivate);
            rsaSignature.update(myEPublic.getEncoded());
            resultKey = rsaSignature.sign();

            return resultKey;

        }catch (java.security.NoSuchAlgorithmException e){ result = "FAILED_signEphemeralPublic_NoSuchAlgorithmException"; }
        catch (java.security.InvalidKeyException e) { result = "FAILED_signEphemeralPublic_InvalidKeyException"; }
        catch (java.security.SignatureException e) { result = "FAILED_signEphemeralPublic_SignatureException"; }


        byte[] result = "SUCCESS".getBytes();
        return result;
    }

    ///////////////check signature/////////////////////////////////////////////
    public boolean checkSignature(byte[] peerSignature, PublicKey peerPublicKey, byte[] peerEkey) {

        try {


            Signature verSignature = Signature.getInstance("SHA256withRSA");
            verSignature.initVerify(peerPublicKey);
            verSignature.update(peerEkey);
            return verSignature.verify(peerSignature);


        }catch(java.security.NoSuchAlgorithmException e) { return false; }
        catch(java.security.InvalidKeyException e) { return false; }
        catch(java.security.SignatureException e) { return false; }

    }


    public PublicKey PublicDecode(byte[] peerPubEnc) {

        try {

            PublicKey peerEPublic;

            KeyFactory peerKeyFactory = KeyFactory.getInstance("EC");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(peerPubEnc);
            peerEPublic = peerKeyFactory.generatePublic(x509KeySpec);

            return peerEPublic;

        }catch(java.security.NoSuchAlgorithmException e) { return null; }
        catch(java.security.spec.InvalidKeySpecException e) { return null; }

    }

    ////////////////generate secret/////////////////////////////////
    public byte[] generateSecret(PrivateKey EphPrivate, PublicKey EphPublicPeer) {

        try {

            byte[] resultGS;

            SecureRandom ransec = new SecureRandom();
            KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");
            keyAgree.init(EphPrivate, ransec);
            keyAgree.doPhase(EphPublicPeer, true);
            resultGS = keyAgree.generateSecret();

            return resultGS;

        }catch(java.security.NoSuchAlgorithmException e) { return null; }
        catch(java.security.InvalidKeyException e) { return null; }

    }

    ////////generate secret key//////////////////////////////////
    public SecretKey generateSecretKey(byte[] secret, byte[] sal) {

        try {
            SecretKey key;

            KeySpec spec = new PBEKeySpec(secret.toString().toCharArray(), sal, 10000, 256);
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2withHmacSHA1");
            key = f.generateSecret(spec);

            return key;

        }catch(java.security.NoSuchAlgorithmException e) { return null; }
        catch(java.security.spec.InvalidKeySpecException e) { return null; }
    }

    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

}
