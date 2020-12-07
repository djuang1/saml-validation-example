package com.dejim;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class SAMLValidator {
	
	public SAMLValidator() {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/*
	public static void main(String[] args) {
		try {
			SAMLValidator samlValidator = new SAMLValidator();
			String valid = validateSAMLResponse("");
			System.out.println(valid);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	*/

	public String validateSAMLResponse(String samlResponse, String keystorePath, String keystorePass, String keyAlias)
			throws ParserConfigurationException, SAXException, IOException, UnmarshallingException, ValidationException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException {

		String assertionString = "";

		/*
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		*/

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
		byte[] base64DecodedResponse = Base64.decode(samlResponse);
		Document document = docBuilder.parse(new ByteArrayInputStream(base64DecodedResponse));
		Element element = document.getDocumentElement();
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);

		XMLObject responseXmlObj = unmarshaller.unmarshall(element);
		Response response = (Response) responseXmlObj;

		//Validates credentials against signature
		KeyStore keyStore = null;
		keyStore = KeyStore.getInstance("JKS");
		java.security.cert.X509Certificate cert = null;
		keyStore.load(new FileInputStream(keystorePath), keystorePass.toCharArray());
		cert = (java.security.cert.X509Certificate) keyStore.getCertificate(keyAlias);

		BasicX509Credential credential = new BasicX509Credential();
		credential.setEntityCertificate(cert);

		SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
		profileValidator.validate(response.getSignature());
		SignatureValidator sigValidator = new SignatureValidator(credential);
		sigValidator.validate(response.getSignature());

		//Gets assertions
		assertionString = response.getAssertions().get(0).getAttributeStatements().get(0).getDOM().getTextContent();

		return assertionString;

	}
}
