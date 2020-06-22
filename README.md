#cryptolib

The aim of cryptolib is to provide a modularized way of supporting crypto implementation of various crypto algorithms
block modes, padding modes, digests, and EcCurves for AES, 3DES, RSA, EC, and HMAC. It provides interfaces and implementation 
for encryption, signature, and HMAC. It supports both FIPS and non-FIPS standards and provides the way to use SunJCE and Bouncy Castle cryto providers.
It will also check if certain padding mode, block mode, EcCurve, or digest is supported or not for a cipher operation?

Clone
=====
git clone https://github.com/irfanazam1/cryptolib.git

Build
=====
- mvn install
- mvn clean package install
- mvn clean package install -DskipTests

Including in the project
=====
 - Maven
 
          <dependency>
             <groupId>cryptlib</groupId>
             <artifactId>cryptolib</artifactId>
             <version>1.0.0</version>
         </dependency>
 
 Usage
 ====
  
        //Create key Authorizations
         KeyAuthorizations keyAuthorizations = new KeyAuthorizations (128, Algorithm.AES, BlockMode.CBC, PaddingMode.NO_PADDING, Purpose.ENCRYPT);
         //Create the material (key and IV)
         byte[] key = new byte[16];
         byte[] iv = new byte[16];
         SecureRandom random = new SecureRandom();
         random.nextBytes(key);
         random.nextBytes(iv);
         //Setup the key symmetric key
         SymmetricKey symmetricKey = new SymmetricKey();
         symmetricKey.setEncodedKey(key);
         symmetricKey.setIv(iv);
         keyAuthorizations.setKey(symmetricKey);
         //Set the provider
         keyAuthorizations.setProvider(new BouncyCastleProvider());
         //Grab the cipher suite for the authorized algorithm
         CipherSuite cipherSuite = CipherSuiteFactory.getCipherSuite(keyAuthorizations);
         //Setup the data.
         byte[] plainBytes = "TextToEncryption".getBytes(Charset.defaultCharset());
         //Encrypt
         byte[] encryptedBytes = cipherSuite.encrypt(plainBytes);
         //Decrypt.
         keyAuthorizations.setPurpose(Purpose.DECRYPT);
         cipherSuite = CipherSuiteFactory.getCipherSuite(keyAuthorizations);
         byte[] decryptedBytes = cipherSuite.decrypt(encryptedBytes, plainBytes.length);
         System.out.println(Arrays.equals(decryptedBytes, plainBytes));  
 
         