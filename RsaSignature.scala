
/*

Sign and verify using RSA in Scala. Runs in Scala REPL interpreter. See
comments below to first create a PKCS8 public/private key pair.




Run in Scala REPL
$> scala -classpath commons-codec-1.10.jar (only needed if using Base64 stuff)
scala> :load test.scala
scala> val x = RsaSignature
scala> x.run



*/

object RsaSignature {

	val PUBLIC_KEY_FILE = "rsa4096_public.der"
	val PRIVATE_KEY_FILE = "rsa4096_private.der"

	def loadBytesfromPkcs8File(filename:String):Array[Byte] = {
		import java.nio.file.{Files, Paths}
		val byteArray = Files.readAllBytes(Paths.get(filename))
		byteArray
	}


	import java.security.{PrivateKey,PublicKey,Signature,KeyFactory}
	import java.security.spec.{X509EncodedKeySpec, PKCS8EncodedKeySpec}

	def getPrivate:PrivateKey = {
		//		val privateKeyBytes:Array[Byte] = loadBytesfromPkcs8File("rsa4096_private.der")
		//		val spec:PKCS8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes)
		//		val kf:KeyFactory = KeyFactory.getInstance("RSA")
		//		kf.generatePrivate(spec)

		// Just for the fun of one hard to read line:
		KeyFactory.getInstance("RSA")
				  .generatePrivate(new PKCS8EncodedKeySpec(loadBytesfromPkcs8File(PRIVATE_KEY_FILE)))

	}

	def getPublic:PublicKey = {
		val publicKeyBytes:Array[Byte] = loadBytesfromPkcs8File(PUBLIC_KEY_FILE)
		val spec:X509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes)
		val kf:KeyFactory = KeyFactory.getInstance("RSA")
		kf.generatePublic(spec)

	}
	
	def sign(privateKey:PrivateKey, plainText:Array[Byte]) : Array[Byte] = {
		val signer = Signature.getInstance("SHA1withRSA")
		signer.initSign(privateKey)
		signer.update(plainText)
		signer.sign()
	}

	def verify(publicKey:PublicKey, signedCipherTest:Array[Byte], plainText:Array[Byte]) : Boolean = {

		val signer = Signature.getInstance("SHA1withRSA")
		signer.initVerify(publicKey)
		signer.update(plainText)
		signer.verify(signedCipherTest)


	}

	// ref: https://gist.github.com/urcadox/6173812
	def encrypt(publicKey:PublicKey, plainText:Array[Byte]) : Array[Byte] = {
		import javax.crypto.{Cipher}
		val cipher = Cipher.getInstance("RSA")
		cipher.init(Cipher.ENCRYPT_MODE, publicKey)
		cipher.doFinal(plainText)

	}




	def run = {

		val privateKey:PrivateKey 	= getPrivate
		val publicKey:PublicKey 	= getPublic
		val plainText:String = "Hello there. It's from me!"

		// Sign
		val signatureData:Array[Byte] = sign(privateKey, plainText.getBytes)
		// import org.apache.commons.codec.binary.Base64
		// println(s"${signedData.size} byte signature: " + Base64.encodeBase64(signedData, false, true).toString)
		
		// Verify
		val verified:Boolean = verify(publicKey, signatureData, plainText.getBytes)
		println(s"Verified: ${verified}")

	}



}


/*

Build the key files

Take a string, hash it. Then digitally sign that hash with your private key. Send
it to someone who has your public key. They run verify() using your public key. 
Assuming they know (or you also give them the thing you're verifying) then if 
verify returns true, they know that the private key corresponding to the public key
they have was used to make the signature.

# hash (not really important)
echo "mythingname" | openssl sha1 > name_sha1.txt

# generate rsa key pair

# private key
openssl genrsa -out rsa4096_private.pem 4096

# public key
openssl rsa -in rsa4096_private.pem -pubout
openssl rsa -in rsa4096_private.pem -pubout -outform DER -out rsa4096_public.der
# Sign / verify
# https://www.openssl.org/docs/manmaster/apps/rsautl.html
#
#sign (from stdin, use ctrl-d to end)

# Test sign and verify from the command line using the generated keys.
# Sign
openssl rsautl -sign -inkey rsa4096_private.pem -out sigfile.rsa

# Verify (presents string originally from stdin)
openssl rsautl -verify -in sigfile.rsa -inkey rsa4096_public.pem -pubin

# if openssl sha1 > name_sha1.txt == "mythingname", then the 
# private key used to sign the hash of this name is authenticated

# all in one line
echo "myvehiclename" | openssl sha1 | openssl rsautl -sign -inkey rsa4096_private.pem | openssl rsautl -verify -inkey rsa4096_public.pem -pubin; echo "myvehiclename" | openssl sha1


########
# now do this all in scala
#######

#http://stackoverflow.com/a/19387517/3680466
#Convert private Key to PKCS#8 format (so Java can read it)
openssl pkcs8 -topk8 -inform PEM -outform DER -in rsa4096_private.pem -out rsa4096_private.der -nocrypt

#http://stackoverflow.com/a/19387517/3680466
#Output public key portion in DER format (so Java can read it)



References:
https://gist.github.com/urcadox/6173812
https://docs.oracle.com/javase/7/docs/api/index.html?javax/crypto/Cipher.html
http://stackoverflow.com/a/19387517/3680466
http://www.programcreek.com/java-api-examples/java.security.Signature
http://codeartisan.blogspot.com/2009/05/public-key-cryptography-in-java.html
http://developer.android.com/reference/javax/crypto/package-summary.html
http://www.logikdev.com/tag/javax-crypto/
http://docs.oracle.com/javase/1.5.0/docs/guide/security/jsse/JSSERefGuide.html#HowSSLWorks
http://stackoverflow.com/questions/5140425/openssl-command-line-to-verify-the-signature/5141195#5141195
https://www.openssl.org/docs/manmaster/apps/rsautl.html
http://connect2id.com/products/nimbus-jose-jwt/openssl-key-generation
https://www.madboa.com/geek/openssl/#how-do-i-create-an-md5-or-sha1-digest-of-a-file
https://commons.apache.org/proper/commons-codec/archives/1.10/apidocs/index.html



*/
