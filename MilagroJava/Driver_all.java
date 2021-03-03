import java.security.SecureRandom;
import java.util.Arrays;
import MilagroLib.*;
import Protocols.*;

public class Driver_all {

    //verify partial private key 
    private static void verifyS(ECP pkS_, ECP lpk_, ECP gen_, BIG S_, BIG hash_){
        ECP testS = new ECP();
        testS = pkS_.mul(hash_);
        testS.add(lpk_);

        if (testS.toString().equals(gen_.mul(S_).toString())) {
            System.out.println("Verfication Sucessful!");
        } else {
            System.out.println("Verfication Failed!");
        }
    }

    //print bytes
    private static void printBinary(byte[] array) {
        int i;
        for (i = 0; i < array.length; i++) {
            System.out.printf("%02x", array[i]);
        }
        System.out.println();
    }

    public static void main(String[] args)
    {
        BIG hashA, hashB;
        byte[] keyA_IBAKA, keyB_IBAKA, keyA_CLAKA, keyB_CLAKA, keyA_MQV, keyB_MQV;
        SecureRandom random = new SecureRandom();
    	RAND rng = new RAND();        
        byte[] RAW = new byte[100];
        byte[] AliceID = new byte[128];
        byte[] BobID = new byte[128];

        //random number generator
        random.nextBytes(RAW);
        random.nextBytes(AliceID);
        random.nextBytes(BobID);
    	rng.clean();
    	rng.seed(100,RAW);

        //declare two parties
        System.out.println("\nMQV process starting...");
        MQV Alice1 = new MQV(rng);
        MQV Bob1 = new MQV(rng);

        //generate principal keys
        Alice1.generateKeys();
        Bob1.generateKeys();

        //calculate keys
        keyA_MQV = Alice1.calculateKey(Bob1.getPublicEphemeralKey(), Bob1.getPublicLongtermKey());
        keyB_MQV = Bob1.calculateKey(Alice1.getPublicEphemeralKey(), Alice1.getPublicLongtermKey());

        //display both parties keys
        System.out.print("\nAlice key: ");
        printBinary(keyA_MQV);
        System.out.print("Bobby key: ");
        printBinary(keyB_MQV);
        
        //success if both keys are same
        if (Arrays.equals(keyA_MQV, keyB_MQV)) {
            System.out.print("\nMQV Key share Sucessful!\n");
        } else {
            System.out.print("\nMQV Key share Failed!\n");
        }

        System.out.println("\n----------------------------------------------------------------------");

        //declare two parties
        System.out.println("\nIBAKA process starting...");
        IBAKA Alice2 = new IBAKA(rng);
        IBAKA Bob2 = new IBAKA(rng);

        //get parameters from KGC
        Alice2.KGC(AliceID); 
        Bob2.KGC(BobID);
        
        hashA = IBAKA.hashing(AliceID, Alice2.getPublicLongtermKey(), Alice2.getHash1(), Alice2.getOrder());
        hashB = IBAKA.hashing(BobID, Bob2.getPublicLongtermKey(), Bob2.getHash1(), Bob2.getOrder());
        
        //verify partial private keys given by KGC
        System.out.print("\nAlice SA: ");
        verifyS(Bob2.getPublicKGCKey(), Alice2.getPublicLongtermKey(), Alice2.getGen(), Alice2.getS(), hashA);
        System.out.print("Bobby SB: ");
        verifyS(Bob2.getPublicKGCKey(), Bob2.getPublicLongtermKey(), Bob2.getGen(), Bob2.getS(), hashB);
        
        //generate ephemeral keys
        Alice2.generateEphemeralKey();
        Bob2.generateEphemeralKey();
        
        //calculate keys
        keyA_IBAKA = Alice2.calculateKey(hashB, Bob2.getPublicLongtermKey(), Bob2.getPublicEphemeralKey());
        keyB_IBAKA = Bob2.calculateKey(hashA, Alice2.getPublicLongtermKey(), Alice2.getPublicEphemeralKey());
       
        //display both parties keys
        System.out.print("\nAlice key: ");
        printBinary(keyA_IBAKA);
        System.out.print("Bobby key: ");
        printBinary(keyB_IBAKA);

        //success if both keys are same
        if (Arrays.equals(keyA_IBAKA, keyB_IBAKA)) {
            System.out.print("\nIBAKA Key share Sucessful!\n");
        } else {
            System.out.print("\nIBAKA Key share Failed!\n");
        }

        System.out.println("\n----------------------------------------------------------------------");
        
        //declare two parties
        System.out.println("\nCLAKA process starting...");
        CLAKA Alice3 = new CLAKA(rng);
        CLAKA Bob3 = new CLAKA(rng);

        //get parameters from KGC
        Alice3.KGC(AliceID); 
        Bob3.KGC(BobID);
        
        hashA = CLAKA.hashing(AliceID, Alice3.getKGCRandomKey(), Alice3.getHash1(), Alice3.getOrder());
        hashB = CLAKA.hashing(BobID, Bob3.getKGCRandomKey(), Bob3.getHash1(), Bob3.getOrder());
        
        //verify partial private keys given by KGC
        System.out.print("\nAlice SA: ");
        verifyS(Bob3.getPublicKGCKey(), Alice3.getKGCRandomKey(), Alice3.getGen(), Alice3.getS(), hashA);
        System.out.print("Bobby SB: ");
        verifyS(Bob3.getPublicKGCKey(), Bob3.getKGCRandomKey(), Bob3.getGen(), Bob3.getS(), hashB);
        
        //generate principal keys
        Alice3.generateEphemeralKey();
        Bob3.generateEphemeralKey();
        
        //calculate keys
        keyA_CLAKA = Alice3.calculateKey(BobID, hashB, Bob3.getKGCRandomKey(), Bob3.getPublicEphemeralKey(), Bob3.getPublicLongtermKey(), true);
        keyB_CLAKA = Bob3.calculateKey(AliceID, hashA, Alice3.getKGCRandomKey(), Alice3.getPublicEphemeralKey(), Alice3.getPublicLongtermKey(), false);
       
        //display both parties keys
        System.out.print("\nAlice key: ");
        printBinary(keyA_CLAKA);
        System.out.print("Bobby key: ");
        printBinary(keyB_CLAKA);

        //success if both keys are same
        if (Arrays.equals(keyA_CLAKA, keyB_CLAKA)) {
            System.out.print("\nCLAKA Key share Sucessful!\n");
        } else {
            System.out.print("\nCLAKA Key share Failed!\n");
        }
    } 
}