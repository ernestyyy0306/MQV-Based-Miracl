package com.example.mqv_sim;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.example.mqv_sim.MilagroLib.BIG;
import com.example.mqv_sim.MilagroLib.ECP;
import com.example.mqv_sim.MilagroLib.RAND;
import com.example.mqv_sim.Protocols.CLAKA;
import com.example.mqv_sim.Protocols.IBAKA;
import com.example.mqv_sim.Protocols.MQV;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Arrays;

public class homeScreen extends AppCompatActivity {
    Thread Thread1 = null;
    EditText etIP, etPort;
    TextView tvMessages;
    Button btnMQV, btnIBAKA, btnCLAKA, btnBenchmark;
    String SERVER_IP;
    int SERVER_PORT;
    boolean benchmark;
    boolean startedMQV = false;
    boolean startedIBAKA = false;
    boolean startedCLAKA = false;
    Thread1 mqv;
    Thread2 ibaka;
    Thread3 claka;
    static int keeplongterm_MQV = 0;
    static int keeplongterm_IBAKA = 0;
    static int keeplongterm_CLAKA = 0;
    static long calTime = 0;
    static long exTime = 0;
    static long genTimeMQV = 0;
    static long genTimeIBAKA = 0;
    static long genTimeCLAKA = 0;
    static long calculateKeyTime = 0;
    static long exchangeKeyTime = 0;
    static long generateKeyTime = 0;
    static MQV client_MQV;
    static IBAKA client_IBAKA;
    static CLAKA client_CLAKA;

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

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_home_screen);

        etIP = findViewById(R.id.etIP);
        etPort = findViewById(R.id.etPort);
        tvMessages = findViewById(R.id.tvMessages);
        btnMQV = findViewById(R.id.MQV);
        btnIBAKA = findViewById(R.id.IBAKA);
        btnCLAKA = findViewById(R.id.CLAKA);
        btnBenchmark = findViewById(R.id.btnBenchmark);

        benchmark = false;
        SecureRandom random = new SecureRandom();
        RAND rng = new RAND();
        byte[] RAW = new byte[100];
        byte[] clientID = new byte[128];
        random.nextBytes(clientID);
        random.nextBytes(RAW);
        rng.clean();
        rng.seed(100,RAW);

        btnMQV.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(mqv != null){mqv.interrupt();}
                if(ibaka != null){ibaka.interrupt();}
                if(claka != null){claka.interrupt();}
                SERVER_IP = etIP.getText().toString().trim();
                if(SERVER_IP.equals("")){
                    SERVER_IP = "10.0.2.2";
                }
                try{
                    SERVER_PORT = Integer.parseInt(etPort.getText().toString().trim());
                }catch (Exception e){
                    SERVER_PORT = 6666;
                }
                mqv = new Thread1(rng, benchmark);
                mqv.start();
            }
        });

        btnIBAKA.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(mqv != null){mqv.interrupt();}
                if(ibaka != null){ibaka.interrupt();}
                if(claka != null){claka.interrupt();}
                SERVER_IP = etIP.getText().toString().trim();
                if(SERVER_IP.equals("")){
                    SERVER_IP = "10.0.2.2";
                }
                try{
                    SERVER_PORT = Integer.parseInt(etPort.getText().toString().trim());
                }catch (Exception e){
                    SERVER_PORT = 6666;
                }
                ibaka = new Thread2(clientID, rng, benchmark);
                ibaka.start();
            }
        });

        btnCLAKA.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(mqv != null){mqv.interrupt();}
                if(ibaka != null){ibaka.interrupt();}
                if(claka != null){claka.interrupt();}
                SERVER_IP = etIP.getText().toString().trim();
                if(SERVER_IP.equals("")){
                    SERVER_IP = "10.0.2.2";
                }
                try{
                    SERVER_PORT = Integer.parseInt(etPort.getText().toString().trim());
                }catch (Exception e){
                    SERVER_PORT = 6666;
                }
                claka = new Thread3(clientID, rng, benchmark);
                claka.start();
            }
        });

        btnBenchmark.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(mqv != null){mqv.interrupt();}
                if(ibaka != null){ibaka.interrupt();}
                if(claka != null){claka.interrupt();}
                if(benchmark){
                    benchmark = false;
                    btnBenchmark.setBackgroundColor(getResources().getColor(R.color.blue_dark));
                }
                else{
                    benchmark = true;
                    btnBenchmark.setBackgroundColor(getResources().getColor(R.color.blue_light));
                }
            }
        });

    }

    class Thread1 extends Thread {
        private byte[] longterm, ephemeral;
        private Socket socket;
        private OutputStream output;
        private InputStream input;
        private boolean benchmark;
        private RAND rng;
        private int longtermChg, ephemeralChg;

        Thread1(RAND rng_, boolean benchmark_){
            ephemeral = new byte[65];
            longterm = new byte[65];
            benchmark = benchmark_;
            rng = rng_;
            generateKeyTime = 0;
            exchangeKeyTime = 0;
            calculateKeyTime = 0;
            if(!startedMQV){
                long start = System.nanoTime();
                client_MQV = new MQV(rng);
                genTimeMQV = (System.nanoTime() - start) / 1000;
                generateKeyTime += genTimeMQV;
                startedMQV = true;
            }
        }

        public void run() {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    tvMessages.setText("Information:\n");
                    tvMessages.append("\nWaiting for data...\n");
                    tvMessages.append("Wrong Port if Slow...");
                }
            });
            longtermChg = 1;
            ephemeralChg = 1;
            if(benchmark){
                longtermChg = 100;
                ephemeralChg = 10;
            }
            for(int i=0; i<longtermChg; i++) {
                if (keeplongterm_MQV > 9) {
                    long start = System.nanoTime();
                    client_MQV = new MQV(rng);
                    genTimeMQV = (System.nanoTime() - start) / 1000;
                    generateKeyTime += genTimeMQV;
                    keeplongterm_MQV = 0;
                }
                int count = 0;
                while (count < ephemeralChg){
                    try {
                        socket = new Socket(SERVER_IP, SERVER_PORT);
                        output = socket.getOutputStream();
                        input = socket.getInputStream();
                        output.write(0x0FF);

                        output.write(MQV.ECP_to_byte(client_MQV.getPublicLongtermKey()));
                        input.read(longterm);

                        long start = System.nanoTime();
                        client_MQV.generateEphemeralKey();
                        output.write(MQV.ECP_to_byte(client_MQV.getPublicEphemeralKey()));
                        input.read(ephemeral);
                        exTime = (System.nanoTime() - start) / 1000;
                        exchangeKeyTime += exTime;

                        String longtermStr = Byte_to_String(MQV.ECP_to_byte(client_MQV.getPublicLongtermKey())).substring(0, 10) + "\n";
                        String ephemeralStr = Byte_to_String(MQV.ECP_to_byte(client_MQV.getPublicEphemeralKey())).substring(0, 10) + "\n";
                        start = System.nanoTime();
                        client_MQV.generateKeys();
                        byte[] keyA = client_MQV.calculateKey(ECP.fromBytes(ephemeral), ECP.fromBytes(longterm));
                        calTime = (System.nanoTime() - start) / 1000;
                        calculateKeyTime += calTime;

                        count++;
                        keeplongterm_MQV++;
                        socket.close();
                        if(Thread.currentThread().isInterrupted()){
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    tvMessages.setText("Information:\n");
                                    tvMessages.append("\nBenchmark Stopped...\n");
                                }
                            });
                            return;
                        }
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                tvMessages.setText("Information: ");
                                if(benchmark){tvMessages.append("Benchmarking...");}
                                tvMessages.append("\n\nMQV Key Exchange...\n");
                                tvMessages.append("\nClient: \n");
                                tvMessages.append("Longterm: " + longtermStr);
                                tvMessages.append("Ephemeral: " + ephemeralStr);
                                tvMessages.append("\nServer: \n");
                                tvMessages.append("Longterm: " + Byte_to_String(longterm).substring(0, 10) + "\n");
                                tvMessages.append("Ephemeral: " + Byte_to_String(ephemeral).substring(0, 10) + "\n");
                                tvMessages.append("\nClient Key: " + Byte_to_String(keyA).substring(0, 10) + "\n");
                                tvMessages.append("\nGenerate Key Time: " + genTimeMQV + " microseconds\n");
                                tvMessages.append("Exchange Key Time: " + exTime + " microseconds\n");
                                tvMessages.append("Calculate Key Time: " + calTime + " microseconds\n");
                                tvMessages.append("\nTotal Time: " + (genTimeMQV + exTime + calTime) + " microseconds\n");
                            }
                        });
                    } catch (Exception e) {
                        e.printStackTrace();
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                tvMessages.setText("Information:\n");
                                tvMessages.append("\nNo Connection Detected!");
                            }
                        });
                    }
                }
            }
            if(benchmark){
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        int totalKeyCount = ephemeralChg * longtermChg;
                        tvMessages.setText("Information: Benchmark Result... \n");
                        tvMessages.append("\nAverage:");
                        tvMessages.append("\nGenerate Key Time for " + totalKeyCount + ": " + generateKeyTime/longtermChg + " us");
                        tvMessages.append("\nExchange Key Time for " + totalKeyCount + ": " + exchangeKeyTime/totalKeyCount + " us");
                        tvMessages.append("\nCalculate Key Time for " + totalKeyCount + ": " + calculateKeyTime/totalKeyCount + " us");
                        long totalTime = (generateKeyTime/longtermChg) + (exchangeKeyTime/totalKeyCount) + (calculateKeyTime/totalKeyCount);
                        tvMessages.append("\n\nTotal Time for " + totalKeyCount + ": " + totalTime + " us\n");
                    }
                });
            }
        }
    }

    class Thread2 extends Thread {
        private byte[] longterm, ephemeral, receiveLong, sendLong, clientID, serverID, clientKey;
        private Socket socket;
        private OutputStream output;
        private InputStream input;
        private RAND rng;
        private boolean benchmark, verify;
        private BIG serverHash, clientHash;
        private int longtermChg, ephemeralChg;
        private byte[] test;

        Thread2(byte[] clientID_, RAND rng_, boolean benchmark_){
            longterm = new byte[65];
            ephemeral = new byte[65];
            receiveLong = new byte[258];
            sendLong = new byte[258];
            serverID = new byte[128];
            clientID = new byte[128];
            test = new byte[1];
            clientID = clientID_;
            rng = rng_;
            benchmark = benchmark_;
            generateKeyTime = 0;
            exchangeKeyTime = 0;
            calculateKeyTime = 0;
            if(!startedIBAKA){
                long start = System.nanoTime();
                client_IBAKA = new IBAKA(rng);
                client_IBAKA.KGC(clientID);
                genTimeIBAKA = (System.nanoTime() - start) / 1000;
                generateKeyTime += genTimeIBAKA;
                startedIBAKA = true;
            }
        }

        public void run() {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    tvMessages.setText("Information:\n");
                    tvMessages.append("\nWaiting for data...\n");
                    tvMessages.append("Wrong Port if Slow...");
                }
            });
            longtermChg = 1;
            ephemeralChg = 1;
            if(benchmark){
                longtermChg = 100;
                ephemeralChg = 10;
            }
            for(int i = 0; i<longtermChg; i++){
                if (keeplongterm_IBAKA > 9) {
                    long start = System.nanoTime();
                    client_IBAKA = new IBAKA(rng);
                    client_IBAKA.KGC(clientID);
                    genTimeIBAKA = (System.nanoTime() - start) / 1000;
                    generateKeyTime += genTimeIBAKA;
                    keeplongterm_IBAKA = 0;
                }
                int count = 0;
                while(count < ephemeralChg){
                    try{
                        socket = new Socket(SERVER_IP, SERVER_PORT);
                        output = socket.getOutputStream();
                        input = socket.getInputStream();
                        output.write(0x0EE);
                        clientHash= IBAKA.hashing(clientID, client_IBAKA.getPublicLongtermKey(), client_IBAKA.getHash1(), client_IBAKA.getOrder());
                        if(verifyS(client_IBAKA.getPublicKGCKey(), client_IBAKA.getPublicLongtermKey(), client_IBAKA.getGen(), client_IBAKA.getS(), clientHash)){
                            verify = true;
                        }
                        else{
                            verify = false;
                        }
                        String longtermClient = Byte_to_String(IBAKA.ECP_to_byte(client_IBAKA.getPublicLongtermKey())).substring(0,10) + "\n";

                        output.write(0x0AB);
                        input.read(test);

                        long start = System.nanoTime();
                        client_IBAKA.generateEphemeralKey();

                        System.arraycopy(clientID, 0, sendLong, 0, clientID.length);
                        System.arraycopy(IBAKA.ECP_to_byte(client_IBAKA.getPublicLongtermKey()), 0, sendLong, 128, 65);
                        System.arraycopy(IBAKA.ECP_to_byte(client_IBAKA.getPublicEphemeralKey()), 0, sendLong, 193, 65);
                        output.write(sendLong);
                        input.read(receiveLong);

                        serverID = Arrays.copyOfRange(receiveLong, 0, 128);
                        longterm = Arrays.copyOfRange(receiveLong, 128, 193);
                        ephemeral = Arrays.copyOfRange(receiveLong, 193, 258);

                        exTime = (System.nanoTime() - start)/1000;
                        exchangeKeyTime += exTime;

                        String ephemeralClient = Byte_to_String(IBAKA.ECP_to_byte(client_IBAKA.getPublicEphemeralKey())).substring(0,10) + "\n";

                        start = System.nanoTime();
                        serverHash = IBAKA.hashing(serverID, ECP.fromBytes(longterm), client_IBAKA.getHash1(), client_IBAKA.getOrder());
                        clientKey = client_IBAKA.calculateKey(serverHash, ECP.fromBytes(longterm), ECP.fromBytes(ephemeral));
                        calTime = (System.nanoTime() - start)/1000;
                        calculateKeyTime += calTime;

                        keeplongterm_IBAKA++;
                        count++;
                        socket.close();
                        if(Thread.currentThread().isInterrupted()){
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    tvMessages.setText("Information:\n");
                                    tvMessages.append("\nBenchmark Stopped...\n");
                                }
                            });
                            return;
                        }
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                tvMessages.setText("Information: ");
                                if(benchmark){tvMessages.append("Benchmarking...");}
                                tvMessages.append("\n\nIBAKA Key Exchange...\n");
                                if(verify){tvMessages.append("Partial Private Key Verification Success!\n");}
                                else{tvMessages.append("Partial Private Key Verification Fail!\n");}
                                tvMessages.append("KGC Public Key: " + Byte_to_String(IBAKA.ECP_to_byte(client_IBAKA.getPublicKGCKey())).substring(0,10) + "\n");

                                tvMessages.append("\nClient:\n");
                                tvMessages.append("ID: " + Byte_to_String(clientID).substring(0,10) + "\n");
                                tvMessages.append("Longterm Key: " + longtermClient);
                                tvMessages.append("Ephemeral Key: " + ephemeralClient);

                                tvMessages.append("\nServer:\n");
                                tvMessages.append("ID: " + Byte_to_String(serverID).substring(0,10) + "\n");
                                tvMessages.append("Longterm Key: " + Byte_to_String(longterm).substring(0,10) + "\n");
                                tvMessages.append("Ephemeral Key: " + Byte_to_String(ephemeral).substring(0,10) + "\n");
                                tvMessages.append("\nClient Key: " + Byte_to_String(clientKey).substring(0,10) + "\n");
                                tvMessages.append("\nGenerate Key Time: " + genTimeIBAKA + " microseconds\n");
                                tvMessages.append("Exchange Key Time: " + exTime + " microseconds\n");
                                tvMessages.append("Calculate Key Time: " + calTime + " microseconds\n");
                                tvMessages.append("\nTotal Time: " + (genTimeIBAKA+exTime+calTime) + " microseconds\n");
                            }
                        });
                    }catch (IOException e){
                        e.printStackTrace();
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                tvMessages.setText("Information:\n");
                                tvMessages.append("\nNo Connection Detected!");
                                return;
                            }
                        });
                    }
                }
            }
            if(benchmark){
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        int totalKeyCount = ephemeralChg * longtermChg;
                        tvMessages.setText("Information: Benchmark Result... \n");
                        tvMessages.append("\nAverage:");
                        tvMessages.append("\nGenerate Key Time for " + totalKeyCount + ": " + generateKeyTime/longtermChg + " us");
                        tvMessages.append("\nExchange Key Time for " + totalKeyCount + ": " + exchangeKeyTime/totalKeyCount + " us");
                        tvMessages.append("\nCalculate Key Time for " + totalKeyCount + ": " + calculateKeyTime/totalKeyCount + " us");
                        long totalTime = (generateKeyTime/longtermChg) + (exchangeKeyTime/totalKeyCount) + (calculateKeyTime/totalKeyCount);
                        tvMessages.append("\n\nTotal Time for " + totalKeyCount + ": " + totalTime + " us\n");
                    }
                });
            }
        }
    }

    class Thread3 extends Thread {
        private BIG serverHash, clientHash;
        private RAND rng;
        private byte[] longterm, ephemeral, receiveLong, sendLong, clientID, serverID, randomKGC;
        private Socket socket;
        private OutputStream output;
        private InputStream input;
        private boolean benchmark, verify;
        private int longtermChg, ephemeralChg;

        Thread3(byte[] clientID_, RAND rng_, boolean benchmark_) {
            longterm = new byte[65];
            randomKGC = new byte[65];
            ephemeral = new byte[65];
            receiveLong = new byte[258];
            sendLong = new byte[258];
            serverID = new byte[128];
            clientID = new byte[128];
            clientID = clientID_;
            rng = rng_;
            benchmark = benchmark_;
            generateKeyTime = 0;
            exchangeKeyTime = 0;
            calculateKeyTime = 0;
            if(!startedCLAKA){
                long start = System.nanoTime();
                client_CLAKA = new CLAKA(rng);
                client_CLAKA.KGC(clientID);
                client_CLAKA.generateLongtermKey();
                genTimeCLAKA = (System.nanoTime() - start) / 1000;
                generateKeyTime += genTimeCLAKA;
                startedCLAKA = true;
            }
        }
        @Override
        public void run() {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    tvMessages.setText("Information:\n");
                    tvMessages.append("\nWaiting for data...\n");
                    tvMessages.append("Wrong Port if Slow...");
                }
            });
            longtermChg = 1;
            ephemeralChg = 1;
            if(benchmark){
                longtermChg = 100;
                ephemeralChg = 10;
            }
            for(int i = 0; i<longtermChg; i++){
                if (keeplongterm_CLAKA > 9) {
                    long start = System.nanoTime();
                    client_CLAKA = new CLAKA(rng);
                    client_CLAKA.KGC(clientID);
                    client_CLAKA.generateLongtermKey();
                    genTimeCLAKA = (System.nanoTime() - start) / 1000;
                    generateKeyTime += genTimeCLAKA;
                    keeplongterm_CLAKA = 0;
                }
                int count = 0;
                while(count < ephemeralChg){
                    try{
                        socket = new Socket(SERVER_IP, SERVER_PORT);
                        output = socket.getOutputStream();
                        input = socket.getInputStream();
                        output.write(0x0DD);

                        clientHash= CLAKA.hashing(clientID, client_CLAKA.getKGCRandomKey(), client_CLAKA.getHash1(), client_CLAKA.getOrder());
                        if(verifyS(client_CLAKA.getPublicKGCKey(), client_CLAKA.getKGCRandomKey(), client_CLAKA.getGen(), client_CLAKA.getS(), clientHash)){
                            verify = true;
                        }
                        else{
                            verify = false;
                        }
                        output.write(CLAKA.ECP_to_byte(client_CLAKA.getPublicLongtermKey()));
                        input.read(longterm);

                        String longtermClient = Byte_to_String(CLAKA.ECP_to_byte(client_CLAKA.getPublicLongtermKey())).substring(0,10) + "\n";
                        String randomKGCClient = Byte_to_String(CLAKA.ECP_to_byte(client_CLAKA.getKGCRandomKey())).substring(0,10) + "\n";

                        long start = System.nanoTime();
                        client_CLAKA.generateEphemeralKey();

                        System.arraycopy(clientID, 0, sendLong, 0, clientID.length);
                        System.arraycopy(CLAKA.ECP_to_byte(client_CLAKA.getKGCRandomKey()), 0, sendLong, 128, 65);
                        System.arraycopy(CLAKA.ECP_to_byte(client_CLAKA.getPublicEphemeralKey()), 0, sendLong, 193, 65);
                        output.write(sendLong);
                        input.read(receiveLong);

                        serverID = Arrays.copyOfRange(receiveLong, 0, 128);
                        randomKGC = Arrays.copyOfRange(receiveLong, 128, 193);
                        ephemeral = Arrays.copyOfRange(receiveLong, 193, 258);

                        exTime = (System.nanoTime() - start)/1000;
                        exchangeKeyTime += exTime;

                        String ephemeralClient = Byte_to_String(CLAKA.ECP_to_byte(client_CLAKA.getPublicEphemeralKey())).substring(0,10) + "\n";

                        start = System.nanoTime();
                        serverHash = IBAKA.hashing(serverID, ECP.fromBytes(randomKGC), client_CLAKA.getHash1(), client_CLAKA.getOrder());
                        byte[] clientKey = client_CLAKA.calculateKey(serverID, serverHash, ECP.fromBytes(randomKGC) , ECP.fromBytes(ephemeral), ECP.fromBytes(longterm), true);
                        calTime = (System.nanoTime() - start)/1000;
                        calculateKeyTime += calTime;

                        keeplongterm_CLAKA++;
                        count++;
                        socket.close();
                        if(Thread.currentThread().isInterrupted()){
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    tvMessages.setText("Information:\n");
                                    tvMessages.append("\nBenchmark Stopped...\n");
                                }
                            });
                            return;
                        }
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                tvMessages.setText("Information: ");
                                if(benchmark){tvMessages.append("Benchmarking...");}
                                tvMessages.append("\n\nCLAKA process starting...\n");
                                if(verify){tvMessages.append("Partial Private Key Verification Success!\n"); }
                                else{tvMessages.append("Partial Private Key Verification Fail!\n");}
                                tvMessages.append("KGC Public Key: " + Byte_to_String(CLAKA.ECP_to_byte(client_CLAKA.getPublicKGCKey())).substring(0,10) + "\n");

                                tvMessages.append("\nClient:\n");
                                tvMessages.append("ID: " + Byte_to_String(clientID).substring(0,10) + "\n");
                                tvMessages.append("Longterm Key: " + longtermClient);
                                tvMessages.append("RandomKGC Key: " + randomKGCClient);
                                tvMessages.append("Ephemeral Key: " + ephemeralClient);

                                tvMessages.append("\nServer:\n");
                                tvMessages.append("ID: " + Byte_to_String(serverID).substring(0,10) + "\n");
                                tvMessages.append("Longterm Key: " + Byte_to_String(longterm).substring(0,10) + "\n");
                                tvMessages.append("RandomKGC Key: " + Byte_to_String(randomKGC).substring(0,10) + "\n");
                                tvMessages.append("Ephemeral Key: " + Byte_to_String(ephemeral).substring(0,10) + "\n");
                                tvMessages.append("\nClient Key: " + Byte_to_String(clientKey).substring(0,10) + "\n");
                                tvMessages.append("\nGenerate Key Time: " + genTimeCLAKA + " microseconds\n");
                                tvMessages.append("Exchange Key Time: " + exTime + " microseconds\n");
                                tvMessages.append("Calculate Key Time: " + calTime + " microseconds\n");
                                tvMessages.append("\nTotal Time: " + (genTimeCLAKA+exTime+calTime) + " microseconds\n");
                            }
                        });
                    }catch (IOException e){
                        e.printStackTrace();
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                tvMessages.setText("Information:\n");
                                tvMessages.append("\nNo Connection Detected!");
                                return;
                            }
                        });
                    }
                }
            }
            if(benchmark){
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        int totalKeyCount = ephemeralChg * longtermChg;
                        tvMessages.setText("Information: Benchmark Result... \n");
                        tvMessages.append("\nAverage:");
                        tvMessages.append("\nGenerate Key Time for " + totalKeyCount + ": " + generateKeyTime/longtermChg + " us");
                        tvMessages.append("\nExchange Key Time for " + totalKeyCount + ": " + exchangeKeyTime/totalKeyCount + " us");
                        tvMessages.append("\nCalculate Key Time for " + totalKeyCount + ": " + calculateKeyTime/totalKeyCount + " us");
                        long totalTime = (generateKeyTime/longtermChg) + (exchangeKeyTime/totalKeyCount) + (calculateKeyTime/totalKeyCount);
                        tvMessages.append("\n\nTotal Time for " + totalKeyCount + ": " + totalTime + " us\n");
                    }
                });
            }
        }
    }
}