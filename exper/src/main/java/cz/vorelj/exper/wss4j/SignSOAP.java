package cz.vorelj.exper.wss4j;

import java.io.File;
import java.io.FileWriter;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.w3c.dom.Document;

/**
 * 
 * @author jv
 * 
 * Loads SOAP message from file, signs it a save. WSS4J framework is used.
 * Certificate to sign can be created in windows - run certmgr.msc and export as pfx with private key
 * Certificate alias is necessary to be set. It can be displayed by keytool -list -v -keystore cert.pfx -storetype pkcs12
 *
 * run: SignSOAP ALIAS PASSWORD CERT_FILE input.xml output.xml
 * for example: SignSOAP 5e1ec3ba-0ca2-4698-95c9-a36b33892590 secure ../cert.pfx input.xml output.xml
 */
public class SignSOAP {
	private static String alias;
	private static String password;
	private static String certFile;
	private static String sourceFile;
	private static String targetFile;

	public static void main(String[] args) throws Exception {
		processArgs(args);
		Document doc = load(sourceFile);
		Document signedDoc = sign(doc);
		write(signedDoc, targetFile);
	}

	private static void processArgs(String[] args) {
		alias = args[0];
		password = args[1];
		certFile = args[2];
		sourceFile = args[3];
		targetFile = args[4];
	}

	private static Document sign(Document doc) throws Exception {
		WSSConfig.init();
		Crypto crypto = CryptoFactory.getInstance(getProperties());

		WSSecSignature builder = new WSSecSignature();
		builder.setUserInfo(alias, password);
		builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
		builder.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
		builder.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");

		WSSecHeader secHeader = new WSSecHeader(doc);
		secHeader.insertSecurityHeader();
		Document signedDoc = builder.build(doc, crypto, secHeader);
		return signedDoc;
	}

	private static Properties getProperties() {
		Properties props = new Properties();
		props.setProperty("org.apache.wss4j.crypto.provider", "org.apache.wss4j.common.crypto.Merlin");
		props.setProperty("org.apache.wss4j.crypto.merlin.keystore.type", "pkcs12");
		props.setProperty("org.apache.wss4j.crypto.merlin.keystore.password", password);
		props.setProperty("org.apache.wss4j.crypto.merlin.keystore.alias", alias);
		props.setProperty("org.apache.wss4j.crypto.merlin.keystore.file", certFile);
		return props;
	}

	private static Document load(String path) throws Exception {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder builder = factory.newDocumentBuilder();
		return builder.parse(new File(path));
	}

	static void write(Document doc, String path) throws Exception {
		StreamResult result = new StreamResult(new FileWriter(path));
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.transform(new DOMSource(doc), result);
	}

}
