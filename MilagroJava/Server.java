import java.io.*;
import java.net.*;
import java.security.SecureRandom;
import java.util.Arrays;

import MilagroLib.*;
import Protocols.*;

public class Server {  

    //print bytes
    public static String Byte_to_String(byte[] b1) {
        StringBuilder strBuilder = new StringBuilder();
        for(byte val : b1) {
            strBuilder.append(String.format("%02x", val&0xff));
        }
        return strBuilder.toString();
    }

    private static boolean verifyS(ECP pkS_, ECP lpk_, ECP gen_, BIG S_, BIG hash_){
        ECP testS = new ECP();
        testS = pkS_.mul(hash_);
        testS.add(lpk_);

        if (testS.toString().equals(gen_.mul(S_).toString())) {
            return true;
        } else {
            return false;
        }
    }
    
    static long calculateKeyTime = 0;
    static long exchangeKeyTime = 0;
    static long generateKeyTime = 0;
    static long calTime = 0;
    static long exTime = 0;

    private static void MQV_Protocol(MQV server_, Socket socket_){
        byte[] longterm = new byte[65];
        byte[] ephemeral = new byte[65];

        try{
            InputStream input = socket_.getInputStream();
            OutputStream output = socket_.getOutputStream();

            System.out.println("\nMQV Key Exchange...");

            input.read(longterm);
            output.write(MQV.ECP_to_byte(server_.getPublicLongtermKey()));

            long start = System.nanoTime();
            server_.generateEphemeralKey();
            input.read(ephemeral);
            output.write(MQV.ECP_to_byte(server_.getPublicEphemeralKey()));

            exTime = (System.nanoTime() - start)/1000;
            exchangeKeyTime += exTime;
            
            start = System.nanoTime();
            server_.generateKeys();
            byte[] serverKey = server_.calculateKey(ECP.fromBytes(ephemeral), ECP.fromBytes(longterm));
            calTime = (System.nanoTime() - start)/1000;
            calculateKeyTime += calTime;
            
            System.out.println("\nServer: ");
            System.out.println("Longterm Key: " + Byte_to_String(MQV.ECP_to_byte(server_.getPublicLongtermKey())).substring(0,10));
            System.out.println("Ephemeral Key: " + Byte_to_String(MQV.ECP_to_byte(server_.getPublicEphemeralKey())).substring(0,10));
            
            System.out.println("\nClient: ");
            System.out.println("Longterm Key: " + Byte_to_String(longterm).substring(0,10));
            System.out.println("Ephemeral Key: " + Byte_to_String(ephemeral).substring(0,10));

            System.out.println("\nServer Key: " + Byte_to_String(serverKey).substring(0,10));
        }catch(Exception e){
            System.out.println(e);
        }  
    }

    private static void IBAKA_Protocol(IBAKA server_, Socket socket_, byte[] serverID_){
        BIG serverHash, clientHash;
        byte[] longterm = new byte[65];
        byte[] ephemeral = new byte[65];
        byte[] receiveLong = new byte[258];
        byte[] sendLong = new byte[258];
        byte[] clientID = new byte[128];
        byte[] test = new byte[1];
        try{
            InputStream input = socket_.getInputStream();
            OutputStream output = socket_.getOutputStream();

            System.out.println("\nIBAKA Key Exchange...");
            serverHash= IBAKA.hashing(serverID_, server_.getPublicLongtermKey(), server_.getHash1(), server_.getOrder());
            if(verifyS(server_.getPublicKGCKey(), server_.getPublicLongtermKey(), server_.getGen(), server_.getS(), serverHash)){
                System.out.println("Partial Private Key Verification Successful!");
            }
            else{
                System.out.println("Partial Private Key Verification Fail!"); 
            }

            input.read(test);
            output.write(0x0AB);

            long start = System.nanoTime();
            server_.generateEphemeralKey();

            System.arraycopy(serverID_, 0, sendLong, 0, serverID_.length);
            System.arraycopy(IBAKA.ECP_to_byte(server_.getPublicLongtermKey()), 0, sendLong, 128, 65);
            System.arraycopy(IBAKA.ECP_to_byte(server_.getPublicEphemeralKey()), 0, sendLong, 193, 65);

            input.read(receiveLong);
            output.write(sendLong);
            exTime = (System.nanoTime() - start)/1000;
            exchangeKeyTime += exTime;
            
            clientID = Arrays.copyOfRange(receiveLong, 0, 128);
            longterm = Arrays.copyOfRange(receiveLong, 128, 193);
            ephemeral = Arrays.copyOfRange(receiveLong, 193, 258);

            start = System.nanoTime();
            clientHash = IBAKA.hashing(clientID, ECP.fromBytes(longterm), server_.getHash1(), server_.getOrder());
            byte[] serverKey = server_.calculateKey(clientHash, ECP.fromBytes(longterm), ECP.fromBytes(ephemeral));
            calTime = (System.nanoTime() - start)/1000;
            calculateKeyTime += calTime;
            
            System.out.println("KGC Public Key: " + Byte_to_String(IBAKA.ECP_to_byte(server_.getPublicKGCKey())).substring(0,10));
            System.out.println("\nServer: ");
            System.out.println("ID: " + Byte_to_String(serverID_).substring(0,10));
            System.out.println("longterm Key: " + Byte_to_String(IBAKA.ECP_to_byte(server_.getPublicLongtermKey())).substring(0,10));
            System.out.println("Ephemeral Key: " + Byte_to_String(IBAKA.ECP_to_byte(server_.getPublicEphemeralKey())).substring(0,10));

            System.out.println("\nClient: ");
            System.out.println("ID: " + Byte_to_String(clientID).substring(0,10));
            System.out.println("Longterm Key: " + Byte_to_String(longterm).substring(0,10));
            System.out.println("Ephemeral Key: " + Byte_to_String(ephemeral).substring(0,10));

            System.out.println("\nServer Key: " + Byte_to_String(serverKey).substring(0,10));

        }catch(Exception e){
            System.out.println(e);
        }  
    }

    private static void CLAKA_Protocol(CLAKA server_, Socket socket_, byte[] serverID_){
        BIG serverHash, clientHash;
        byte[] randomKGC = new byte[65];
        byte[] ephemeral = new byte[65];
        byte[] longterm = new byte[65];
        byte[] receiveLong = new byte[258];
        byte[] sendLong = new byte[258];
        byte[] clientID = new byte[128];

        try{
            InputStream input = socket_.getInputStream();
            OutputStream output = socket_.getOutputStream();

            System.out.println("\nCLAKA process starting...");
            serverHash = CLAKA.hashing(serverID_, server_.getKGCRandomKey(), server_.getHash1(), server_.getOrder());
            if(verifyS(server_.getPublicKGCKey(), server_.getKGCRandomKey(), server_.getGen(), server_.getS(), serverHash)){
                System.out.println("Partial Private Key Verification Successful!");}
            else{System.out.println("Partial Private Key Verification Fail!"); }

            input.read(longterm);
            output.write(CLAKA.ECP_to_byte(server_.getPublicLongtermKey()));

            long start = System.nanoTime();
            server_.generateEphemeralKey();
            
            System.arraycopy(serverID_, 0, sendLong, 0, serverID_.length);
            System.arraycopy(CLAKA.ECP_to_byte(server_.getKGCRandomKey()), 0, sendLong, 128, 65);
            System.arraycopy(CLAKA.ECP_to_byte(server_.getPublicEphemeralKey()), 0, sendLong, 193, 65);

            input.read(receiveLong);
            output.write(sendLong);

            clientID = Arrays.copyOfRange(receiveLong, 0, 128);
            randomKGC = Arrays.copyOfRange(receiveLong, 128, 193);
            ephemeral = Arrays.copyOfRange(receiveLong, 193, 258);
            exTime = (System.nanoTime() - start)/1000;
            exchangeKeyTime += exTime;

            
            start = System.nanoTime();
            clientHash = CLAKA.hashing(clientID, ECP.fromBytes(randomKGC), server_.getHash1(), server_.getOrder());
            byte[] serverKey = server_.calculateKey(clientID, clientHash, ECP.fromBytes(randomKGC) , ECP.fromBytes(ephemeral), ECP.fromBytes(longterm), false);
            calTime = (System.nanoTime() - start)/1000;
            calculateKeyTime += calTime;

            System.out.println("KGC Public Key: " + Byte_to_String(CLAKA.ECP_to_byte(server_.getPublicKGCKey())).substring(0,10));
            System.out.println("\nServer: ");
            System.out.println("ID: " + Byte_to_String(serverID_).substring(0,10));
            System.out.println("Longterm Key: " + Byte_to_String(CLAKA.ECP_to_byte(server_.getPublicLongtermKey())).substring(0,10));
            System.out.println("RandomKGC Key: " + Byte_to_String(CLAKA.ECP_to_byte(server_.getKGCRandomKey())).substring(0,10));
            System.out.println("Ephemeral Key: " + Byte_to_String(CLAKA.ECP_to_byte(server_.getPublicEphemeralKey())).substring(0,10));

            System.out.println("\nClient: ");
            System.out.println("ID: " + Byte_to_String(clientID).substring(0,10));
            System.out.println("Longterm Key: " + Byte_to_String(longterm).substring(0,10));
            System.out.println("RandomKGC Key: " + Byte_to_String(randomKGC).substring(0,10));
            System.out.println("Ephemeral Key: " + Byte_to_String(ephemeral).substring(0,10));

            System.out.println("\nServer Key: " + Byte_to_String(serverKey).substring(0,10));

        }catch(Exception e){
            System.out.println(e);
        }  
    }

    public static void main(String[] args){  
        SecureRandom random = new SecureRandom();
    	RAND rng = new RAND();        
        byte[] RAW = new byte[100];
        byte[] ServerID = new byte[128];
        byte[] mode = new byte[1]; 
        
        random.nextBytes(RAW);
        random.nextBytes(ServerID);
        rng.clean();
        rng.seed(100,RAW);

        MQV Server_MQV = new MQV(rng);
        IBAKA Server_IBAKA = new IBAKA(rng);
        Server_IBAKA.KGC(ServerID); 
        CLAKA Server_CLAKA = new CLAKA(rng);
        Server_CLAKA.KGC(ServerID);
        Server_CLAKA.generateLongtermKey();  
        
        long genTime = 0;
        int protocol = 2;
        int longtermChg = 100;
        int ephemeralChg = 10;

        try{
            ServerSocket serverSocket = new ServerSocket(6666); 

            for(int i=0;i<longtermChg;i++){
                if(protocol == 0){
                    long start = System.nanoTime();
                    Server_MQV = new MQV(rng);
                    genTime = (System.nanoTime() - start)/1000;
                }
                else if(protocol == 1){
                    long start = System.nanoTime();
                    Server_IBAKA = new IBAKA(rng);
                    Server_IBAKA.KGC(ServerID); 
                    genTime = (System.nanoTime() - start)/1000;
                } 
                else if(protocol == 2){
                    long start = System.nanoTime();
                    Server_CLAKA = new CLAKA(rng);
                    Server_CLAKA.KGC(ServerID);
                    Server_CLAKA.generateLongtermKey();  
                    genTime = (System.nanoTime() - start)/1000;
                }
                generateKeyTime += genTime;
                int count = 0;
                while(count < ephemeralChg){
                    Socket socket = serverSocket.accept();
                    InputStream input = socket.getInputStream();
                    input.read(mode);
                    if(Byte_to_String(mode).equals("ff")){  
                        MQV_Protocol(Server_MQV, socket); 
                    }
                    else if(Byte_to_String(mode).equals("ee")){  
                        IBAKA_Protocol(Server_IBAKA, socket, ServerID);
                    }
                    else if(Byte_to_String(mode).equals("dd")){  
                        CLAKA_Protocol(Server_CLAKA, socket, ServerID);
                    }
                    System.out.println("\nGenerate Key Time: " + genTime + " microseconds");
                    System.out.println("Exchange Key Time: " + exTime + " microseconds");
                    System.out.println("Calculate Key Time: " + calTime + " microseconds");
                    System.out.println("-----------------------------------------");
                    socket.close();
                    count++;
                }
            }
            serverSocket.close();
        }catch(Exception e){
            System.out.println(e);
        }  
        int totalKeyCount = ephemeralChg * longtermChg;
        System.out.println("\nAverage Generate Key Time for " + totalKeyCount + " Connections: " + generateKeyTime/longtermChg + " microseconds");
        System.out.println("Average Exchange Key Time for " + totalKeyCount + " Connections: " + exchangeKeyTime/totalKeyCount + " microseconds");
        System.out.println("Average Calculate Key Time for " + totalKeyCount + " Connections: " + calculateKeyTime/totalKeyCount + " microseconds");
        long totalTime = (generateKeyTime/longtermChg) + (exchangeKeyTime/totalKeyCount) + (calculateKeyTime/totalKeyCount);
        System.out.println("\nAverage Total Time for " + totalKeyCount + " Connections: " + totalTime + " microseconds\n");
    } 
}  