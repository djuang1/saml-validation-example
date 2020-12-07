package com.dejim;

import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;

import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;

import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import org.opensaml.xml.util.Base64;

import java.util.UUID;
import java.io.StringWriter;
import org.joda.time.DateTime;

import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class AuthNRequestBuilder {

	private static final String SAML2_NAME_ID_POLICY = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
	private static final String SAML2_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
	private static final String SAML2_POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
	private static final String SAML2_PASSWORD_PROTECTED_TRANSPORT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
	private static final String SAML2_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";

	public AuthNRequestBuilder() {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public String generateAuthNRequest(String assertionConsumerServiceUrl, String issuerId, String destinationUrl, String providerName) {

		String samlRequest = null;

		try {
			AuthNRequestBuilder authReqBuilder = new AuthNRequestBuilder();
			AuthnRequest authNRequest = authReqBuilder.buildAuthenticationRequest(assertionConsumerServiceUrl,
					issuerId, destinationUrl, providerName);
			samlRequest = generateSAMLRequest(authNRequest);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return samlRequest;
	}

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

		assertionString = response.getAssertions().get(0).getAttributeStatements().get(0).getDOM().getTextContent();

		return assertionString;

	}

	/*
	public static void main(String[] args) {

		try {
			
			AuthNRequestBuilder authReqBuilder = new AuthNRequestBuilder();
			AuthnRequest authNRequest = authReqBuilder.buildAuthenticationRequest("http://localhost:8081/callback",
					"http://localhost:8081", "https://djuang1-dev-ed.my.salesforce.com/idp/login?app=0sp3m000000TOFf");
			
			String valid = validateSAMLResponse("");
			System.out.println(valid);
			
			String samlRequest = generateSAMLRequest(authNRequest);

			System.out.println(samlRequest);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	*/

	public String generateSAMLRequest(AuthnRequest authRequest) throws Exception {

		Marshaller marshaller = org.opensaml.Configuration.getMarshallerFactory().getMarshaller(authRequest);
		org.w3c.dom.Element authDOM = marshaller.marshall(authRequest);
		StringWriter rspWrt = new StringWriter();
		XMLHelper.writeNode(authDOM, rspWrt);
		String messageXML = rspWrt.toString();

		/*
		 * System.out.println(messageXML); Deflater deflater = new
		 * Deflater(Deflater.DEFLATED, true); ByteArrayOutputStream
		 * byteArrayOutputStream = new ByteArrayOutputStream(); DeflaterOutputStream
		 * deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream,
		 * deflater); deflaterOutputStream.write(messageXML.getBytes());
		 * deflaterOutputStream.close();
		 */		
		// String samlRequest = Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);
		// return URLEncoder.encode(samlRequest, "UTF-8");
		
		String samlRequest = Base64.encodeBytes(messageXML.getBytes(), Base64.DONT_BREAK_LINES);
		return samlRequest;
	}

	/**
	 * Generate an authentication request.
	 * 
	 * @return AuthnRequest Object
	 */
	public AuthnRequest buildAuthenticationRequest(String assertionConsumerServiceUrl, String issuerId, String destinationUrl, String providerName) {

		// Generate ID
		DateTime issueInstant = new DateTime();
		AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
		AuthnRequest authRequest = authRequestBuilder.buildObject(SAML2_PROTOCOL, "AuthnRequest", "samlp");
		
		// authRequest.setForceAuthn(Boolean.FALSE);
		// authRequest.setIsPassive(Boolean.FALSE);
		authRequest.setNameIDPolicy(buildNameIDPolicy());
		// authRequest.setRequestedAuthnContext(buildRequestedAuthnContext());
		
		authRequest.setDestination(destinationUrl);
		//authRequest.setProviderName(providerName);
		authRequest.setIssueInstant(issueInstant);
		authRequest.setProtocolBinding(SAML2_POST_BINDING);
		authRequest.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);
		authRequest.setIssuer(buildIssuer(issuerId));
		authRequest.setID(UUID.randomUUID().toString());
		authRequest.setVersion(SAMLVersion.VERSION_20);

		return authRequest;
	}

	/**
	 * Build the issuer object
	 * 
	 * @return Issuer object
	 */
	private static Issuer buildIssuer(String issuerId) {
		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(issuerId);
		return issuer;
	}

	/**
	 * Build the NameIDPolicy object
	 * 
	 * @return NameIDPolicy object
	 */
	private static NameIDPolicy buildNameIDPolicy() {
		NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
		nameIDPolicy.setFormat(SAML2_NAME_ID_POLICY);
		nameIDPolicy.setAllowCreate(Boolean.TRUE);
		return nameIDPolicy;
	}

	/**
	 * Build the RequestedAuthnContext object
	 * 
	 * @return RequestedAuthnContext object
	 */
	private static RequestedAuthnContext buildRequestedAuthnContext() {

		// Create AuthnContextClassRef
		AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
		AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject(SAML2_ASSERTION,
				"AuthnContextClassRef", "saml");
		authnContextClassRef.setAuthnContextClassRef(SAML2_PASSWORD_PROTECTED_TRANSPORT);

		// Create RequestedAuthnContext
		RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
		RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
		requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
		requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

		return requestedAuthnContext;
	}
}
