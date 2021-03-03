package com.example.mqv_sim.Protocols;

import com.example.mqv_sim.MilagroLib.*;

public class MQV {

    //private variables declaration
    private BIG order, esk, halfByteBig, lsk, S, epk_;
    private ECP gen, epk, key1, lpk;
    private byte[] key;
    private HASH256 hash;
    private RAND rng;

    //constructor
    public MQV(RAND rng_){
        long[] halfByteLong = { 0x0L, 0x0L, 0x4000L, 0x0L, 0x0L };  //half byte of curve order
        hash = new HASH256();               //SHA256
        gen = ECP.generator();              //generator
        order = new BIG(ROM.CURVE_Order);   //order
        halfByteBig = new BIG(halfByteLong);
        rng = rng_;
        lsk = BIG.randomnum(order, rng);    //longterm secret key, a
        lpk = gen.mul(lsk);                 //longterm public key, A = a*P
    }

    //generate ephemeral, longterm and private keys
    public void generateKeys(){
        epk_ = epk.getX();                  //get X coordinate from X
        epk_.mod(halfByteBig);              //modulus with half byte of curve order
        epk_.add(halfByteBig);              //X_bar = (x mod {half_byte}) + {half_byte}

        S = BIG.mul(epk_, lsk).mod(order);  //SA = X_bar * a mod {order}
        S.add(esk);                         //SA = x + (X_bar * a mod {order})
        S.mod(order);                       //SA = (x + (X_bar * a mod {order})) mode {order}
    }

    public void generateEphemeralKey(){
        esk = BIG.randomnum(order, rng);    //ephemeral secret key, x
        epk = gen.mul(esk);                 //ephemeral public key, X = x*P
    }

    public ECP getPublicLongtermKey(){return lpk;}  //return public longterm key
    public ECP getPublicEphemeralKey(){return epk;} //return public ephemeral key

    //generate share key
    public byte[] calculateKey(ECP ephemeral, ECP longterm){
        BIG ephemeral_;                     //Y_bar
        ephemeral_ = ephemeral.getX();      //Y_bar = y
        ephemeral_.mod(halfByteBig);        //Y_bar = y mod {half_byte}
        ephemeral_.add(halfByteBig);        //Y_bar = (y mod {half_byte}) + {half_byte}
        
        key1 = longterm.mul(ephemeral_);    //key = B * Y_bar
        key1.add(ephemeral);                //key = B * Y_bar + Y
        key1 = key1.mul(S);                 //key = (B * Y_bar + Y) * SA = SA * SB * P

        key = hashing(key1, hash, order);   //hash with SHA256
        return key;
    }

    //SHA256
    public static byte[] hashing(ECP key_, HASH256 hash_, BIG order_){
        byte[] hash_byte, key_byte;

        key_byte = new byte[65];
        key_.toBytes(key_byte, false);

        for (int i = 0; i < key_byte.length; i++){
            hash_.process(key_byte[i]);
        }
        hash_byte = hash_.hash();

        return hash_byte;
    }

    //elliptic curve porint to byte
    public static byte[] ECP_to_byte(ECP ecp){
        byte[] temp = new byte[65];
        ecp.toBytes(temp, false);
        return temp;
    }
}
