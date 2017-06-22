import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import com.safenetinc.jcprov.CK_ATTRIBUTE;
import com.safenetinc.jcprov.CK_BBOOL;
import com.safenetinc.jcprov.CK_C_INITIALIZE_ARGS;
import com.safenetinc.jcprov.CK_MECHANISM;
import com.safenetinc.jcprov.CK_OBJECT_HANDLE;
import com.safenetinc.jcprov.CK_SESSION_HANDLE;
import com.safenetinc.jcprov.Cryptoki;
import com.safenetinc.jcprov.CryptokiEx;
import com.safenetinc.jcprov.LongRef;
import com.safenetinc.jcprov.constants.CKA;
import com.safenetinc.jcprov.constants.CKF;
import com.safenetinc.jcprov.constants.CKK;
import com.safenetinc.jcprov.constants.CKM;
import com.safenetinc.jcprov.constants.CKO;
import com.safenetinc.jcprov.constants.CKU;
import com.safenetinc.jcprov.constants.CK_KEY_TYPE;
import com.safenetinc.jcprov.constants.CK_OBJECT_CLASS;


public class CreateRsaKeys {

	private static final String APPLICATION_NAME = "CreateRsaKeys";
	private static int SLOT = -1;
	private static String PASSWD = "";
	private static String PRIVATE_KEY_LABEL = "";
	private static String PUBLIC_KEY_LABEL = "";
	private static int KEY_SIZE = 1024;
	private static boolean SALT = true;
	
	  
	  private void processCommandLine(String[] args) throws ParseException
	    {
		  
			//Key sizes acceptable
			ArrayList<Integer> list = new ArrayList<Integer>();
			list.add(512); //Non-FIPS mode only
			list.add(1024);
			list.add(2048);
			list.add(3072);
			list.add(4096);
			list.add(8192);
			
			ArrayList<String> listChars = new ArrayList<String>();
			listChars.add("a-z");
			listChars.add("A-Z");
			listChars.add("0-9");
			listChars.add("-");
			listChars.add("_");
			listChars.add(".");
			
	        Option slotIdOption = new Option("s", "slot", true, "slot identifier");
	        Option slotPasswordOption = new Option("p", "password", true, "partition password");
	        Option privateKeyLabelOption = new Option("pr", "privateKeyLabel", true, "Valid chars: " + listChars.toString());
	        Option publicKeyLabelOption = new Option("pu", "publicKeyLabel", true, "Valid chars: " + listChars.toString());
	        Option keySizeOption = new Option("k", "keySize", true, "Valid sizes: " + list.toString());
	        Option saltOption = new Option("sa", "salt", true, "yes / no");

	        Options commandLineOptions = new Options();
	        commandLineOptions.addOption(slotIdOption);
	        commandLineOptions.addOption(slotPasswordOption);
	        commandLineOptions.addOption(privateKeyLabelOption);
	        commandLineOptions.addOption(publicKeyLabelOption);
	        commandLineOptions.addOption(keySizeOption);
	        commandLineOptions.addOption(saltOption);
	        

            
	        CommandLineParser clp = new DefaultParser();

	        try
	        {
	            CommandLine cl = clp.parse(commandLineOptions, args);
	            
	            /* SLOT ID CHECKING */
	            String slotIdOptionValue = cl.getOptionValue('s');
	            if(slotIdOptionValue == null)
	            {
	                throw new ParseException("[Error-1] Slot ID argument is missing. Traverse to [Luna_Folder]/bin and run `vtl listSlots` and check slot list.");
	            }
	            else{
	            	//Set Slot into global var
	            	SLOT = Integer.parseInt(slotIdOptionValue);
	            }
	            /**************************************************************/
	            
	            /* PARTITION PASSWORD CHECKING*/
	            String slotPasswordOptionValue = cl.getOptionValue('p');	            
	            if(slotPasswordOptionValue == null)
	            {
	            	throw new ParseException("[Error-2] Partition password is missing");
	            }
	            else{
	            	PASSWD = slotPasswordOptionValue;
	            }
	            
	            /**************************************************************/
	           
	            /* PRIVATE KEY CHECKING*/
	            String privateKeyLabelOptionValue = cl.getOptionValue("pr");	            
	            if(privateKeyLabelOptionValue == null)
	            {
	            	throw new ParseException("[Error-3] Private Key Label is missing. Give a name with NO spaces. Allowed: " + listChars.toString());	                
	            }
	            else{
	            	PRIVATE_KEY_LABEL = privateKeyLabelOptionValue;
	            }
	            /**************************************************************/
	            
	            /* PUBLIC KEY CHECKING*/
	            String publicKeyLabelOptionValue = cl.getOptionValue("pu");	            
	            if(publicKeyLabelOptionValue == null)
	            {
	            	throw new ParseException("[Error-4] Public Key Label is missing. Give a name with NO spaces. Allowed " + listChars.toString());	                
	            }
	            else{
	            	PUBLIC_KEY_LABEL = publicKeyLabelOptionValue;
	            }
	            /**************************************************************/

	            /* KEY SIZE*/
	            String keySizeOptionValue = cl.getOptionValue("k");	            
	            if(keySizeOptionValue == null)
	            {
	            	throw new ParseException("[Error-5] Key Size is missing. Acceptable values are: " + list.toString());	                
	            }
	            else{
	            	if (list.contains(Integer.parseInt(keySizeOptionValue))){
	            		KEY_SIZE = Integer.parseInt(keySizeOptionValue);
	            	}
	            	else{
	            		throw new ParseException("[Error-6] Key Size not acceptable. Use one of these: " + list.toString());
	            	}
	            }
	            /**************************************************************/

	            /* SALT*/
	            String saltOptionValue = cl.getOptionValue("sa");	            
	            if(saltOptionValue == null)
	            {
	            	throw new ParseException("[Error-7] Salt is missing. Acceptable values are: yes / no");	                
	            }
	            else{
	            	if (saltOptionValue.contentEquals("yes")){
	            		SALT = true;
	            		
	            	}
	            	else {
	            		if (saltOptionValue.contentEquals("no")){
	            			SALT  = false;
	            		}
	            		else{
		            		throw new ParseException("[Error-8] Salt value incorrect. Use: yes / no only");
		            	}
	            	}	            	
	            }
	            /**************************************************************/
	        }
	        catch(ParseException pe)
	        {
	            System.out.println(pe.getMessage());
	            HelpFormatter formatter = new HelpFormatter();

	            formatter.printHelp(APPLICATION_NAME, commandLineOptions, true);

	            //System.out.println(pe.getMessage());
	            
	            throw pe;
	        }
	    }
	  
	  public static CK_OBJECT_HANDLE findKeyObjectWithUniqueLabel(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_CLASS objectClass, CK_KEY_TYPE keyType, String keyLabel) throws DuplicateCrytoKiObjectsFoundException
	    {
	        // We assume that there could be more than one object with the same label and therefore cater for the return of a maximum of two object handles
	        CK_OBJECT_HANDLE[] objectHandlesFound = { new CK_OBJECT_HANDLE(), new CK_OBJECT_HANDLE() };

	        // Holds the total number of key objects found that match the search criteria
	        LongRef totalObjectsFound = new LongRef();

	        // Define attribute search template that will locate all key objects of a particular key type that have a specific label
	        CK_ATTRIBUTE[] searchAttributeTemplate =
	        {
	            new CK_ATTRIBUTE(CKA.CLASS, objectClass),
	            new CK_ATTRIBUTE(CKA.KEY_TYPE, keyType),
	            new CK_ATTRIBUTE(CKA.LABEL, keyLabel.getBytes()),
	        };

	        // Find key objects as defined by attribute search template
	        CryptokiEx.C_FindObjectsInit(sessionHandle, searchAttributeTemplate, searchAttributeTemplate.length);
	        CryptokiEx.C_FindObjects(sessionHandle, objectHandlesFound, objectHandlesFound.length, totalObjectsFound);
	        CryptokiEx.C_FindObjectsFinal(sessionHandle);

	        // Did we fail to find any key objects that match the search criteria?
	        if(totalObjectsFound.value == 0)
	        {
	            // Return an invalid object handle to inidicate that we didn't find a key that matches the search criteria
	            return new CK_OBJECT_HANDLE();
	        }
	        
	        // Did we find two objects of the same type with the same key label?
	        if(totalObjectsFound.value != 1)
	        {
	            // We found two objects of the same type with the same key label
	            throw new DuplicateCrytoKiObjectsFoundException();
	        }
	        
	        // Return the single key object that matched the search critera
	        return objectHandlesFound[0];
	    }
	  
	  public CreateRsaKeys(String[] args) throws Exception
	    {
	        super();
	
	        try 
	        {
	        	System.out.println("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
	        	System.out.println(APPLICATION_NAME);
	        	System.out.println("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n");
	            processCommandLine(args);
	            
	            //Open HSM connection        
	            CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));
	            try
	            {
	                CK_SESSION_HANDLE sessionHandle = new CK_SESSION_HANDLE();
	                CryptokiEx.C_OpenSession(SLOT, CKF.RW_SESSION|CKF.SERIAL_SESSION, null, null, sessionHandle);
	                System.out.println("Session Opened");
	                try
	                {
	                    try
	                    {
	                        CryptokiEx.C_Login(sessionHandle, CKU.USER, PASSWD.getBytes(), PASSWD.length());
	                        System.out.println("Login finished");
	                        CK_OBJECT_HANDLE privateKeyHandle = findKeyObjectWithUniqueLabel(sessionHandle,
	                            CKO.PRIVATE_KEY, CKK.RSA, PRIVATE_KEY_LABEL);
	                        System.out.println("Private key with the given label already exists?");
	                        // Did we get handle to private key?
	                        if(privateKeyHandle.isValidHandle() == true)
	                        {
	                        	System.out.println(">Private Key with the label " + PRIVATE_KEY_LABEL + " already exists, aborting key pair generation");
	                            // Private key with specified label already exists
	                        	throw new ParseException("Private Key with the label " + PRIVATE_KEY_LABEL + " already exists, aborting key pair generation");
	                        }
	                        else
	                        {
	                        	System.out.println(">No, we are good to proceed");
	                        }
	                        System.out.println("Starting Generate Key Pair process");
	                        // Generate key pair
	                        generateKeyPair(sessionHandle);
	                        
	                    }
	                    finally
	                    {
	                        Cryptoki.C_Logout(sessionHandle);
	                        System.out.println("Logout done");
	                    }
	                }
	                finally
	                {
	                    Cryptoki.C_CloseSession(sessionHandle);
	                    System.out.println("Session closed");
	                }
	            }
	            finally
	            {
	                Cryptoki.C_Finalize(null);
	                System.out.println("Library finalized");
	            }       
	    }
	    catch(ParseException pe)
	    {
	        return;
	    }
	  }
	  
 
	  private void generateKeyPair(CK_SESSION_HANDLE sessionHandle) throws DuplicateCrytoKiObjectsFoundException
	    {
	        CK_MECHANISM mechanism;
	        if (SALT){
	        	mechanism = new CK_MECHANISM(CKM.RSA_X9_31_KEY_PAIR_GEN, null);
	        	System.out.println("Salt is ON");
	        } else {
	        	mechanism = new CK_MECHANISM(CKM.RSA_PKCS_KEY_PAIR_GEN, null);
	        	System.out.println("Salt is OFF");
	        }
	                    
	        CK_ATTRIBUTE[] publicKeyAttributeTemplate =
	        {
	        	//SET CKA.TOKEN TO TRUE TO HAVE THE KEY WITHIN THE HSM. IF FALSE, IT WON'T BE STORED. 
	            //new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.FALSE),
	        	new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
	            new CK_ATTRIBUTE(CKA.PRIVATE, CK_BBOOL.TRUE),
	            new CK_ATTRIBUTE(CKA.MODIFIABLE, CK_BBOOL.FALSE),
	            new CK_ATTRIBUTE(CKA.DERIVE, CK_BBOOL.FALSE),
	            new CK_ATTRIBUTE(CKA.ENCRYPT, CK_BBOOL.FALSE),
	            new CK_ATTRIBUTE(CKA.VERIFY, CK_BBOOL.FALSE),
	            new CK_ATTRIBUTE(CKA.VERIFY_RECOVER, CK_BBOOL.FALSE),
	            new CK_ATTRIBUTE(CKA.WRAP, CK_BBOOL.TRUE),
	            new CK_ATTRIBUTE(CKA.MODULUS_BITS, KEY_SIZE),
	            new CK_ATTRIBUTE(CKA.PUBLIC_EXPONENT, RSAKeyGenParameterSpec.F4.toByteArray()),
	            new CK_ATTRIBUTE(CKA.LABEL, PUBLIC_KEY_LABEL),            
	        };
	        /////////////FOR DEBUG
	        //printArray(publicKeyAttributeTemplate);
	        ///////////////////
	        CK_ATTRIBUTE[] privateKeyAttributeTemplate =
	        {
	            new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
	            new CK_ATTRIBUTE(CKA.PRIVATE, CK_BBOOL.TRUE),
	            new CK_ATTRIBUTE(CKA.MODIFIABLE, CK_BBOOL.TRUE),
	            new CK_ATTRIBUTE(CKA.DERIVE, CK_BBOOL.FALSE),
	            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE),
	            new CK_ATTRIBUTE(CKA.DECRYPT, CK_BBOOL.FALSE),
	            new CK_ATTRIBUTE(CKA.SIGN, CK_BBOOL.FALSE),
	            new CK_ATTRIBUTE(CKA.SIGN_RECOVER, CK_BBOOL.FALSE),
	            new CK_ATTRIBUTE(CKA.UNWRAP, CK_BBOOL.TRUE),
	            new CK_ATTRIBUTE(CKA.EXTRACTABLE, CK_BBOOL.FALSE),
	            new CK_ATTRIBUTE(CKA.LABEL, PRIVATE_KEY_LABEL),
	            //new CK_ATTRIBUTE(CKA.USAGE_LIMIT, 20), // Ensure this private key can only be used a maximum of 20 times
	            //new CK_ATTRIBUTE(CKA.USAGE_COUNT, 0),
	        };
	        //printArray(publicKeyAttributeTemplate);
	        CK_OBJECT_HANDLE publicKeyHandle = new CK_OBJECT_HANDLE();
	        CK_OBJECT_HANDLE privateKeyHandle = new CK_OBJECT_HANDLE();

	        System.out.println("Calling GenerateKeyPair method");
	        CryptokiEx.C_GenerateKeyPair(sessionHandle, mechanism,
	            publicKeyAttributeTemplate, publicKeyAttributeTemplate.length, 
	            privateKeyAttributeTemplate, privateKeyAttributeTemplate.length, publicKeyHandle, privateKeyHandle);

	        
	        System.out.println(">Keys generated sucessfully");
	        CK_OBJECT_HANDLE privateKeyHandleChecking = findKeyObjectWithUniqueLabel(sessionHandle,
			    CKO.PRIVATE_KEY, CKK.RSA, PRIVATE_KEY_LABEL);
			System.out.println("Private key is in the HSM? Let me check...");
			// Did we get handle to private key?
			if(privateKeyHandleChecking.isValidHandle() == true)
			{
				System.out.println(">Yes, it is!");
			}
			else
			{
				System.out.println(">No, try to run the program again.");
			}
			System.out.println("Finished key pair generation.");
	    }
	  
	  public static void main(String[] args) throws Exception {		  
		  new CreateRsaKeys(args);
	  }
	}
