import java.security.SecureRandom;
import java.util.Arrays;
import MilagroLib.*;
import Protocols.CLAKA;

public class Driver_CLAKA {

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
        byte[] keyA, keyB;
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
        System.out.println("\nCLAKA process starting...");
        CLAKA Alice = new CLAKA(rng);
        CLAKA Bob = new CLAKA(rng);

        //get parameters from KGC
        Alice.KGC(AliceID); 
        Bob.KGC(BobID);
        
        hashA = CLAKA.hashing(AliceID, Alice.getKGCRandomKey(), Alice.getHash1(), Alice.getOrder());
        hashB = CLAKA.hashing(BobID, Bob.getKGCRandomKey(), Bob.getHash1(), Bob.getOrder());
        
        //verify partial private keys given by KGC
        System.out.print("\nAlice SA: ");
        verifyS(Bob.getPublicKGCKey(), Alice.getKGCRandomKey(), Alice.getGen(), Alice.getS(), hashA);
        System.out.print("Bobby SB: ");
        verifyS(Bob.getPublicKGCKey(), Bob.getKGCRandomKey(), Bob.getGen(), Bob.getS(), hashB);
        
        //generate principal keys
        Alice.generateEphemeralKey();
        Bob.generateEphemeralKey();
        
        //calculate keys
        keyA = Alice.calculateKey(BobID, hashB, Bob.getKGCRandomKey(), Bob.getPublicEphemeralKey(), Bob.getPublicLongtermKey(), true);
        keyB = Bob.calculateKey(AliceID, hashA, Alice.getKGCRandomKey(), Alice.getPublicEphemeralKey(), Alice.getPublicLongtermKey(), false);
       
        //display both parties keys
        System.out.print("\nAlice key: ");
        printBinary(keyA);
        System.out.print("Bobby key: ");
        printBinary(keyB);

        //success if both keys are same
        if (Arrays.equals(keyA, keyB)) {
            System.out.print("\nCLAKA Key share Sucessful!\n");
        } else {
            System.out.print("\nCLAKA Key share Failed!\n");
        }

    } 
}