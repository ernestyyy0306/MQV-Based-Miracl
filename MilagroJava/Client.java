import java.io.*;
import java.net.*;
import java.security.SecureRandom;
import java.util.Arrays;

import MilagroLib.*;
import Protocols.*;

public class Client {  
    
    static long calculateKeyTime = 0;
    static long exchangeKeyTime = 0;
    static long generateKeyTime = 0;
    static long calTime = 0;
    static long exTime = 0;

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

    public static String Byte_to_String(byte[] b1) {
        StringBuilder strBuilder = new StringBuilder();
        for(byte val : b1) {
            strBuilder.append(String.format("%02x", val&0xff));
        }
        return strBuilder.toString();
    }  

    private static void MQV_Protocol(MQV client_, Socket socket_){
        byte[] longterm = new byte[65];
        byte[] ephemeral = new byte[65];
        try{
            OutputStream output = socket_.getOutputStream();
            InputStream input = socket_.getInputStream();
            output.write(0x0FF);

            System.out.println("\nMQV Key Exchange...");
           
            output.write(MQV.ECP_to_byte(client_.getPublicLongtermKey()));
            input.read(longterm);

            long start = System.nanoTime();
            client_.generateEphemeralKey();
            output.write(MQV.ECP_to_byte(client_.getPublicEphemeralKey()));
            input.read(ephemeral);
            exTime = (System.nanoTime() - start)/1000;
            exchangeKeyTime += exTime;

            start = System.nanoTime();
            client_.generateKeys();
            byte[] clientKey = client_.calculateKey(ECP.fromBytes(ephemeral), ECP.fromBytes(longterm));
            calTime = (System.nanoTime() - start)/1000;
            calculateKeyTime += calTime;

            System.out.println("\nClient: ");
            System.out.println("Longterm: " + Byte_to_String(MQV.ECP_to_byte(client_.getPublicLongtermKey())).substring(0,10));
            System.out.println("Ephemeral: " + Byte_to_String(MQV.ECP_to_byte(client_.getPublicEphemeralKey())).substring(0,10));
            
            System.out.println("\nServer: ");
            System.out.println("Longterm: " + Byte_to_String(longterm).substring(0,10));
            System.out.println("Ephemeral: " + Byte_to_String(ephemeral).substring(0,10));
            
            System.out.println("\nClient Key: " + Byte_to_String(clientKey).substring(0,10));
            socket_.close();
        }catch(Exception e){
            System.out.println(e);
        }
    }

    private static void IBAKA_Protocol(IBAKA client_, Socket socket_, byte[] clientID_){
        BIG serverHash, clientHash;
        byte[] longterm = new byte[65];
        byte[] ephemeral = new byte[65];
        byte[] receiveLong = new byte[258];
        byte[] sendLong = new byte[258];
        byte[] serverID = new byte[128];
        byte[] test = new byte[1];
        try{
            InputStream input = socket_.getInputStream();
            OutputStream output = socket_.getOutputStream();

            System.out.println("\nIBAKA Key Exchange...");
            output.write(0x0EE);
            clientHash= IBAKA.hashing(clientID_, client_.getPublicLongtermKey(), client_.getHash1(), client_.getOrder());
            if(verifyS(client_.getPublicKGCKey(), client_.getPublicLongtermKey(), client_.getGen(), client_.getS(), clientHash)){
                System.out.println("Partial Private Key Verification Successful!");
            }
            else{
                System.out.println("Partial Private Key Verification Fail!"); 
            }
            
            output.write(0x0AB);
            input.read(test);

            long start = System.nanoTime();
            client_.generateEphemeralKey();

            System.arraycopy(clientID_, 0, sendLong, 0, clientID_.length);
            System.arraycopy(IBAKA.ECP_to_byte(client_.getPublicLongtermKey()), 0, sendLong, 128, 65);
            System.arraycopy(IBAKA.ECP_to_byte(client_.getPublicEphemeralKey()), 0, sendLong, 193, 65);

            output.write(sendLong);
            input.read(receiveLong);

            serverID = Arrays.copyOfRange(receiveLong, 0, 128);
            longterm = Arrays.copyOfRange(receiveLong, 128, 193);
            ephemeral = Arrays.copyOfRange(receiveLong, 193, 258);
            exTime = (System.nanoTime() - start)/1000;
            exchangeKeyTime += exTime;

            start = System.nanoTime();
            serverHash = IBAKA.hashing(serverID, ECP.fromBytes(longterm), client_.getHash1(), client_.getOrder());
            byte[] clientKey = client_.calculateKey(serverHash, ECP.fromBytes(longterm), ECP.fromBytes(ephemeral));
            calTime = (System.nanoTime() - start)/1000;
            calculateKeyTime += calTime;
            
            System.out.println("KGC Public Key: " + Byte_to_String(IBAKA.ECP_to_byte(client_.getPublicKGCKey())).substring(0,10));
            System.out.println("\nClient: ");
            System.out.println("ID: " + Byte_to_String(clientID_).substring(0,10));
            System.out.println("Longterm Key: " + Byte_to_String(IBAKA.ECP_to_byte(client_.getPublicLongtermKey())).substring(0,10));
            System.out.println("Ephemeral Key: " + Byte_to_String(IBAKA.ECP_to_byte(client_.getPublicEphemeralKey())).substring(0,10));
            
            System.out.println("\nServer: ");
            System.out.println("ID: " + Byte_to_String(serverID).substring(0,10));
            System.out.println("Longterm Key: " + Byte_to_String(longterm).substring(0,10));
            System.out.println("Ephemeral Key: " + Byte_to_String(ephemeral).substring(0,10));

            System.out.println("\nClient Key: " + Byte_to_String(clientKey).substring(0,10));

        }catch(Exception e){
            System.out.println(e);
        }  
    }

    private static void CLAKA_Protocol(CLAKA client_, Socket socket_, byte[] clientID_){
        BIG serverHash, clientHash;
        byte[] randomKGC = new byte[65];
        byte[] ephemeral = new byte[65];
        byte[] longterm = new byte[65];
        byte[] receiveLong = new byte[258];
        byte[] sendLong = new byte[258];
        byte[] serverID = new byte[128];

        try{
            InputStream input = socket_.getInputStream();
            OutputStream output = socket_.getOutputStream();

            System.out.println("\nCLAKA process starting...");
            output.write(0x0DD);
            clientHash = CLAKA.hashing(clientID_, client_.getKGCRandomKey(), client_.getHash1(), client_.getOrder());
            if(verifyS(client_.getPublicKGCKey(), client_.getKGCRandomKey(), client_.getGen(), client_.getS(), clientHash)){
                System.out.println("Partial Private Key Verification Successful!");}
            else{System.out.println("Partial Private Key Verification Fail!"); }

            output.write(CLAKA.ECP_to_byte(client_.getPublicLongtermKey()));
            input.read(longterm);
            
            long start = System.nanoTime();
            client_.generateEphemeralKey();

            System.arraycopy(clientID_, 0, sendLong, 0, clientID_.length);
            System.arraycopy(CLAKA.ECP_to_byte(client_.getKGCRandomKey()), 0, sendLong, 128, 65);
            System.arraycopy(CLAKA.ECP_to_byte(client_.getPublicEphemeralKey()), 0, sendLong, 193, 65);
            
            output.write(sendLong);
            input.read(receiveLong);

            serverID = Arrays.copyOfRange(receiveLong, 0, 128);
            randomKGC = Arrays.copyOfRange(receiveLong, 128, 193);
            ephemeral = Arrays.copyOfRange(receiveLong, 193, 258);
            exTime = (System.nanoTime() - start)/1000;
            exchangeKeyTime += exTime;

            start = System.nanoTime();
            serverHash = CLAKA.hashing(serverID, ECP.fromBytes(randomKGC), client_.getHash1(), client_.getOrder());
            byte[] clientKey = client_.calculateKey(serverID, serverHash, ECP.fromBytes(randomKGC) , ECP.fromBytes(ephemeral), ECP.fromBytes(longterm), true);
            calTime = (System.nanoTime() - start)/1000;
            calculateKeyTime += calTime;

            System.out.println("KGC Public Key: " + Byte_to_String(CLAKA.ECP_to_byte(client_.getPublicKGCKey())).substring(0,10));
            System.out.println("\nClient: ");
            System.out.println("ID: " + Byte_to_String(clientID_).substring(0,10));
            System.out.println("Longterm Key: " + Byte_to_String(CLAKA.ECP_to_byte(client_.getPublicLongtermKey())).substring(0,10));
            System.out.println("RandomKGC Key: " + Byte_to_String(CLAKA.ECP_to_byte(client_.getKGCRandomKey())).substring(0,10));
            System.out.println("Ephemeral Key: " + Byte_to_String(CLAKA.ECP_to_byte(client_.getPublicEphemeralKey())).substring(0,10));
           
            System.out.println("\nServer: ");
            System.out.println("ID: " + Byte_to_String(serverID).substring(0,10));
            System.out.println("Longterm Key: " + Byte_to_String(longterm).substring(0,10));
            System.out.println("RandomKGC Key: " + Byte_to_String(randomKGC).substring(0,10));
            System.out.println("Ephemeral Key: " + Byte_to_String(ephemeral).substring(0,10));

            System.out.println("\nClient Key: " + Byte_to_String(clientKey).substring(0,10));
        }catch(Exception e){
            System.out.println(e);
        }  
    }

    public static void main(String[] args) {  
        calculateKeyTime = 0;
        exchangeKeyTime = 0;
        generateKeyTime = 0;

        SecureRandom random = new SecureRandom();
        RAND rng = new RAND();
        byte[] RAW = new byte[100];
        byte[] clientID = new byte[128];
        
        random.nextBytes(RAW);
        random.nextBytes(clientID);
        rng.clean();
        rng.seed(100,RAW);

        MQV client_MQV = new MQV(rng);
        IBAKA client_IBAKA = new IBAKA(rng);
        client_IBAKA.KGC(clientID);  
        CLAKA client_CLAKA = new CLAKA(rng);
        client_CLAKA.KGC(clientID);
        client_CLAKA.generateLongtermKey(); 

        String SERVER_IP = "192.168.0.197";
        int SERVER_PORT = 6666;
        long genTime = 0; 
        int protocol = 2;
        int longtermChg = 100;
        int ephemeralChg = 10;

        try{
            for(int i=0; i<longtermChg; i++){
                if(protocol == 0){
                    long start = System.nanoTime();
                    client_MQV = new MQV(rng);
                    genTime = (System.nanoTime() - start)/1000;
                }
                else if(protocol == 1){
                    long start = System.nanoTime();
                    client_IBAKA = new IBAKA(rng);
                    client_IBAKA.KGC(clientID);  
                    genTime = (System.nanoTime() - start)/1000;
                } 
                else if(protocol == 2){
                    long start = System.nanoTime();
                    client_CLAKA = new CLAKA(rng);
                    client_CLAKA.KGC(clientID);
                    client_CLAKA.generateLongtermKey();  
                    genTime = (System.nanoTime() - start)/1000;
                }
                generateKeyTime += genTime;
                int count = 0;
                while(count < ephemeralChg){
                    Socket socket = new Socket(SERVER_IP, SERVER_PORT);
                    if(protocol == 0){
                        MQV_Protocol(client_MQV, socket);
                    }
                    else if(protocol == 1){  
                        IBAKA_Protocol(client_IBAKA, socket, clientID);
                    }
                    else if(protocol == 2){  
                        CLAKA_Protocol(client_CLAKA, socket, clientID);
                    }
                    System.out.println("\nGenerate Key Time: " + genTime + " microseconds");
                    System.out.println("Exchange Key Time: " + exTime + " microseconds");
                    System.out.println("Calculate Key Time: " + calTime + " microseconds");
                    System.out.println("-----------------------------------------");
                    socket.close();
                    count++;
                } 
            }
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