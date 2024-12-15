package com.iasonas.cryptovoip;

import java.net.DatagramSocket;

/**
 This class is used to hold the sockets created by HP request/response and the peer's two endpoints
 */

public class UdpEndpoints {

    public DatagramSocket Sock1;
    public DatagramSocket Sock2;
    public String UdpEndpoint1;
    public String UdpEndpoint2;

    public void setSock1(DatagramSocket one) { Sock1 = one; }
    public DatagramSocket getSock1() { return Sock1; }

    public void setSock2(DatagramSocket two) { Sock2 = two; }
    public DatagramSocket getSock2() { return Sock2; }

    public void setUDP1( String one) { UdpEndpoint1 = one; }
    public String getUDP1() { return UdpEndpoint1; }

    public void setUDP2( String one) { UdpEndpoint2 = one; }
    public String getUDP2() { return UdpEndpoint2; }
}
