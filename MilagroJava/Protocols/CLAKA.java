package Protocols;

import java.io.ByteArrayOutputStream;
import MilagroLib.*;

public class CLAKA {
    
    //private variables declaration
    private static BIG order, skS;
    private static ECP gen, pkS;
    private static HASH256 hash1;
    private static HASH512 hash2;
    private BIG hash, S, lsk, esk, r;
    private ECP lpk, epk, key1, key2, key3, R;
    private RAND rng;
    private byte[] id, key, epk_byte, epk_byte_, key1_byte, key2_byte, key3_byte;

    //constructor
    public CLAKA(RAND rng_){
        rng = rng_;
    }

    public ECP getPublicLongtermKey(){return lpk;}      //return public longterm key, A
    public ECP getPublicKGCKey(){return pkS;}           //return KGC public key, pkS
    public ECP getGen(){return gen;}                    //return generator, P
    public BIG getOrder(){return order;}                //return order of the curve
    public BIG getS(){return S;}                        //return partial private key, S
    public HASH256 getHash1(){return hash1;}            //return first hashing function (SHA256)
    public HASH512 getHash2(){return hash2;}            //return second hashing function (SHA512)
    public ECP getPublicEphemeralKey(){return epk;}     //return public ephemeral key, X
    public ECP getKGCRandomKey(){return R;}             //return KGC chosen private key, R
    
    //generate principal longterm and ephemeral key
    public void generateEphemeralKey(){
        esk = BIG.randomnum(order, rng);    //ephemeral secret key, x
        epk = gen.mul(esk);                 //ephemeral public key, X = x*P
    }

    public void generateLongtermKey(){
        lsk = BIG.randomnum(order, rng);    //longterm secret key, a
        lpk = gen.mul(lsk);                 //longterm public key, A = a*P
    }

    //generate share key
    public byte[] calculateKey(byte[] id_, BIG hash_, ECP R_, ECP epk_, ECP lpk_, boolean initiator){
        ByteArrayOutputStream concatenate = new ByteArrayOutputStream( );
        key1 = pkS.mul(hash_);                      //key1 = pkS*hash(IDA, RA)
        key1.add(R_);                               //key1 = RB + pkS*hash(IDA,RA)
        key1.add(epk_);                             //key1 = Y + RB + pkS*hash(IDA,RA)
        key1 = key1.mul(BIG.modadd(esk, S, order)); //key1 = (Y + SB)(X + SA)

        key2 = new ECP(epk_);   //key2 = Y
        key2.add(lpk_);         //key2 = B + Y
        key2 = key2.mul(BIG.modadd(esk, lsk, order)); //key2 = (B + Y)(A + X)

        key3 = epk_.mul(esk);   //key3 = x*y*P

        //convert key to bytes
        concatenate.reset();
        key1_byte = ECP_to_byte(key1);
        key2_byte = ECP_to_byte(key2);
        key3_byte = ECP_to_byte(key3);
        epk_byte = ECP_to_byte(epk);
        epk_byte_ = ECP_to_byte(epk_);

        //if initiator key = H2(IDA, IDB, epkA, epkB, key1A, key2A ,key3A)
        if (initiator) {
            try{
                //concatenate IDA, IDB, epkA, epkB, key1A, key2A ,key3A
                concatenate.write(id);
                concatenate.write(id_);
                concatenate.write(epk_byte);
                concatenate.write(epk_byte_);
                concatenate.write(key1_byte);
                concatenate.write(key2_byte);
                concatenate.write(key3_byte);
            }catch(Exception e){
                System.out.print("Error!");
            }
            for (int i = 0; i < concatenate.toByteArray().length; i++){
                hash2.process(concatenate.toByteArray()[i]);
            }
        }
        //if responder key = H2(IDA, IDB, epkA, epkB, key1B, key2B ,key3B)
        else{
            try{
                //concatenate IDA, IDB, epkA, epkB, key1B, key2B ,key3B
                concatenate.write(id_);
                concatenate.write(id);
                concatenate.write(epk_byte_);
                concatenate.write(epk_byte);
                concatenate.write(key1_byte);
                concatenate.write(key2_byte);
                concatenate.write(key3_byte);
            }catch(Exception e){
                System.out.print("Error!");
            }
            for (int i = 0; i < concatenate.toByteArray().length; i++){
                hash2.process(concatenate.toByteArray()[i]);
            }
        }
        
        //hash with SHA512
        key = hash2.hash();

        return key;
    }

    //generate order, generator, hash, partial private key, random key by KGC
    public void KGC(byte[] id_){
        RAND set = new RAND();        
        byte[] RAW = new byte[100];
        for (int i=0;i<100;i++) RAW[i]=(byte)(i);
        set.clean();
    	set.seed(100,RAW);      //create constant key for KGC

        id = id_;
        hash1 = new HASH256();  //SHA256
        hash2 = new HASH512();  //SHA512
        gen = ECP.generator();  //generator
        order = new BIG(ROM.CURVE_Order);   //order
        skS = BIG.randomnum(order, set);    //KGC secret key
        pkS = gen.mul(skS);                 //KGC public key
        r = BIG.randomnum(order, rng);      //KGC random secret key
        R = gen.mul(r);                     //KGC random public key

        hash = hashing(id_, R, hash1, order);   //hash with SHA256
        hash.mod(order);
        S = BIG.modadd((BIG.modmul(hash, skS, order)), r, order);   //calculate partial private key
    }

    //SHA256
    public static BIG hashing(byte[] id_, ECP lpk_, HASH256 hash_, BIG order_){
        ByteArrayOutputStream concatenate = new ByteArrayOutputStream( );
        byte[] hash_byte, lpk_byte;
        BIG hash;

        lpk_byte = ECP_to_byte(lpk_);

        try{
            concatenate.write(id_);
            concatenate.write(lpk_byte);
        }catch(Exception e){
            System.out.print("Error!");
        }
        for (int i = 0; i < concatenate.toByteArray().length; i++){
            hash_.process(concatenate.toByteArray()[i]);
        }
        hash_byte = hash_.hash();
        hash = byte_to_BIG(hash_byte);
        hash.mod(order_);
        concatenate.reset();
        return hash;
    }

    //convert from byte to BIG
    private static BIG byte_to_BIG(byte [] array){
        BIG result = new BIG();
        long[] long_ = new long[4];
        for(int i=long_.length; i > 0;i--){
            long_[i-1] =
                ((array[i*7-3] & 0xFFL) << 48) |
                ((array[i*7-2] & 0xFFL) << 40) |
                ((array[i*7-1] & 0xFFL) << 32) |
                ((array[i*7] & 0xFFL) << 24) | 
                ((array[i*7+1] & 0xFFL) << 16) | 
                ((array[i*7+2] & 0xFFL) <<  8) | 
                ((array[i*7+3] & 0xFFL) <<  0) ; 
        }
        int int_ = 
            (int) (((array[0] & 0xFFL) << 24) |
		    ((array[1] & 0xFFL) << 16) |
		    ((array[2] & 0xFFL) << 8) |
		    ((array[3] & 0xFFL) << 0)) ;
        
        long[] temp = {long_[3],long_[2],long_[1],long_[0],int_};

        result = new BIG(temp);
        return result;
    }

    //elliptic curve point to byte
    public static byte[] ECP_to_byte(ECP ecp){
        byte[] temp = new byte[65];
        ecp.toBytes(temp, false);
        return temp;
    }
}
