package com.dejim;

import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;

import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.util.Base64;

import java.util.UUID;
import java.io.StringWriter;
import org.joda.time.DateTime;

import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;

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
	
	public String generateAuthNRequest(String assertionConsumerServiceUrl, String issuerId) {

		String samlRequest = null;
		
		try {
			AuthNRequestBuilder authReqBuilder = new AuthNRequestBuilder();
			AuthnRequest authNRequest = authReqBuilder.buildAuthenticationRequest("http://login.company.com/saml/sso",
					"http://www.okta.com/samlappid");
			samlRequest = generateSAMLRequest(authNRequest);
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return samlRequest;
	}
	
	/*
	public static void main(String[] args) {

		try {
			AuthNRequestBuilder authReqBuilder = new AuthNRequestBuilder();
			AuthnRequest authNRequest = authReqBuilder.buildAuthenticationRequest("http://login.company.com/saml/sso",
					"http://www.okta.com/samlappid");
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

		Deflater deflater = new Deflater(Deflater.DEFLATED, true);
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
		deflaterOutputStream.write(messageXML.getBytes());
		deflaterOutputStream.close();
		String samlRequest = Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);
		return URLEncoder.encode(samlRequest, "UTF-8");
	}

	/**
	 * Generate an authentication request.
	 * 
	 * @return AuthnRequest Object
	 */
	public AuthnRequest buildAuthenticationRequest(String assertionConsumerServiceUrl, String issuerId) {

		// Generate ID
		DateTime issueInstant = new DateTime();
		AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
		AuthnRequest authRequest = authRequestBuilder.buildObject(SAML2_PROTOCOL, "AuthnRequest", "samlp");
		authRequest.setForceAuthn(Boolean.FALSE);
		authRequest.setIsPassive(Boolean.FALSE);
		authRequest.setIssueInstant(issueInstant);
		authRequest.setProtocolBinding(SAML2_POST_BINDING);
		authRequest.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);
		authRequest.setIssuer(buildIssuer(issuerId));
		authRequest.setNameIDPolicy(buildNameIDPolicy());
		authRequest.setRequestedAuthnContext(buildRequestedAuthnContext());
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
