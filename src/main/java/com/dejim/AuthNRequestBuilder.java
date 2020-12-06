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

	public String generateAuthNRequest(String assertionConsumerServiceUrl, String issuerId, String destinationUrl) {

		String samlRequest = null;

		try {
			AuthNRequestBuilder authReqBuilder = new AuthNRequestBuilder();
			AuthnRequest authNRequest = authReqBuilder.buildAuthenticationRequest(assertionConsumerServiceUrl,
					issuerId, destinationUrl);
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

		samlResponse = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbHA6UmVzcG9uc2UgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgRGVzdGluYXRpb249Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MS9jYWxsYmFjayIgSUQ9Il9kODIxYTU0ZDZkM2YwYWQ0MWYwMGVmMGExMWY4NWVjNjE2MDcxMjgyNDIxODkiIEluUmVzcG9uc2VUbz0iZDNiZTU0NzgtZTBlZi00ZjQwLTljMTgtMzk5YmQyYjRkNDg4IiBJc3N1ZUluc3RhbnQ9IjIwMjAtMTItMDVUMDA6MzA6NDIuMTg5WiIgVmVyc2lvbj0iMi4wIj48c2FtbDpJc3N1ZXIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiPmh0dHBzOi8vZGp1YW5nMS1kZXYtZWQubXkuc2FsZXNmb3JjZS5jb208L3NhbWw6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPgo8ZHM6U2lnbmVkSW5mbz4KPGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KPGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPgo8ZHM6UmVmZXJlbmNlIFVSST0iI19kODIxYTU0ZDZkM2YwYWQ0MWYwMGVmMGExMWY4NWVjNjE2MDcxMjgyNDIxODkiPgo8ZHM6VHJhbnNmb3Jtcz4KPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+CjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiPjxlYzpJbmNsdXNpdmVOYW1lc3BhY2VzIHhtbG5zOmVjPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiIFByZWZpeExpc3Q9ImRzIHNhbWwgc2FtbHAgeHMgeHNpIi8+PC9kczpUcmFuc2Zvcm0+CjwvZHM6VHJhbnNmb3Jtcz4KPGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+CjxkczpEaWdlc3RWYWx1ZT4xMHRCUUY4Q1o2UG80d2RjRmtMUUR2WXNwdGs9PC9kczpEaWdlc3RWYWx1ZT4KPC9kczpSZWZlcmVuY2U+CjwvZHM6U2lnbmVkSW5mbz4KPGRzOlNpZ25hdHVyZVZhbHVlPgpVQ3dOYndZTE44R1BQQ29KU3dKU1p6akpZWGpFUWZOaDdyVGtnakZxK2Rsd0ZzdEpNZnp5K3pmaHh3SEg5QVdKbmNDay96bC9QUkZ4CkN1WmtoRFVuWEdaOWZ3Y2V4NjRma3lZM3RkTWRDaFIwKzdETjgveGtxZUlIcWFROEFRUUYwREpUaFQwWlhNN0l2bXVaWk53VFR2Z1MKT3NSQUNncUpHajZ3NURPZFpmSU9QZ1pGWVBUc3FVTDV4dnFBR2lMaml0elpjVXZGd3JZelBUMHJBSWJwM3huRkNPVVIwNVNPb01KVwpPcmY2aHRlckpmbC9Ra2I0L0NYZEIwNWRuYTdOZkt1Y0FYbVRQeVhuWFNqY3ZRK3gzSFNBbDlhcWJaK2k4aHk0a1Q2NDhOWnphaDFQCk9IUml3Yk5ITWJqUXpGaVkrenpGeUpyS3VYdzBQcUpyYW1hMHhBPT0KPC9kczpTaWduYXR1cmVWYWx1ZT4KPGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRVVqQ0NBenFnQXdJQkFnSU9BWFRmNU9TY0FBQUFBRjJhYVpzd0RRWUpLb1pJaHZjTkFRRUxCUUF3ZERFTU1Bb0dBMVVFQXd3RApVMU5QTVJnd0ZnWURWUVFMREE4d01FUnZNREF3TURBd01GcHdPVVV4RnpBVkJnTlZCQW9NRGxOaGJHVnpabTl5WTJVdVkyOXRNUll3CkZBWURWUVFIREExVFlXNGdSbkpoYm1OcGMyTnZNUXN3Q1FZRFZRUUlEQUpEUVRFTU1Bb0dBMVVFQmhNRFZWTkJNQjRYRFRJd01Ea3oKTURFMk5ESXpORm9YRFRJeE1Ea3pNREV5TURBd01Gb3dkREVNTUFvR0ExVUVBd3dEVTFOUE1SZ3dGZ1lEVlFRTERBOHdNRVJ2TURBdwpNREF3TUZwd09VVXhGekFWQmdOVkJBb01EbE5oYkdWelptOXlZMlV1WTI5dE1SWXdGQVlEVlFRSERBMVRZVzRnUm5KaGJtTnBjMk52Ck1Rc3dDUVlEVlFRSURBSkRRVEVNTUFvR0ExVUVCaE1EVlZOQk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0MKQVFFQXArNGNTc1dpT1pnVzNsZTJvYkF6cWZXZy9PNW0ySmZHTXZMVjlDNElOSkp0andkVGZMVWhLZER5d0NDMGxNQVRlbnVvZXpSeQo0aVh1YzExbFhXQ2hsTjg3UUs2eHQ2M3BWbXYrZ1FhV2tWcyt5VmR3MFpGdnp1QzFrZG9lUVRrS0duait6OVpXengra24xN0lFVmtKCmlWZGZ6UVpiR05rSlVSTjByaGl0VUpuWU1CYUZBNWtMMmxMUVNjQUZuS2g5REthN0VhRHk0eWJ5MWFHZUtjK0V1Mlk5aGZPR09tNmoKSGJlRUlXZUpubVNrWTd5WEFxUUhUWUFMSVV2UGtZdE9RL2plTHdRS1Y4ang0c1JsUXpJSG5UUm05SjVRYTFMUkN2SkdIcUNWQldEcwoyL0Q1anREZ2ZUNW1ScEt3MVpHUnV0SGxiSXNYSE5mblZDTGdQd0JIV1FJREFRQUJvNEhoTUlIZU1CMEdBMVVkRGdRV0JCU1VlbzY4Ck9sQTdQSkdGUi85RjdYQlBsbEJvK3pBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUlHckJnTlZIU01FZ2FNd2dhQ0FGSlI2anJ3NlVEczgKa1lWSC8wWHRjRStXVUdqN29YaWtkakIwTVF3d0NnWURWUVFEREFOVFUwOHhHREFXQmdOVkJBc01EekF3Ukc4d01EQXdNREF3V25BNQpSVEVYTUJVR0ExVUVDZ3dPVTJGc1pYTm1iM0pqWlM1amIyMHhGakFVQmdOVkJBY01EVk5oYmlCR2NtRnVZMmx6WTI4eEN6QUpCZ05WCkJBZ01Ba05CTVF3d0NnWURWUVFHRXdOVlUwR0NEZ0YwMytUa25BQUFBQUJkbW1tYk1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQVMKV1hSYlQ3RmpkMlo5R1VlcWozNlAxangvcDhBL3Y1YmVkWlY5N2xyRmRIR2ZJNDBMOVJHSDFlQWZMU0Nlb1J5bUVVSlA4TmZrTWJMbwpweWdYSlBySG1CWndCTjA3YlJlSEJTWjdCV3pIdGRycG9WellxMndhL3YvTzNFVUFGTy9tQ0psTG9Uc2hpeC9TcXBQQzhlVUdYTWpDClMzYWp2QUlpdmtMc051MXZFcWhNbE52WDFJOEZzNUkxMTYwY0tjUnZraFRFY3ZQS3JFOHFKOHJweGxDVDRJUFVoSXlJNlhPYUtRY3kKSm0zN1VDdllYeUhpRlpnTFV5WERVMjZpL29hczBjcXVuQnY4bDZkRC9NSjB6aW9YQXpKajZheWRQN0drMUpjNUIySzFMYTVnNGJodwprZ0F2TE9pRUd6UzJHSlBZcVhtMFBFd2UrRktoaC94YUpWQ1I8L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48c2FtbDpBc3NlcnRpb24geG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgSUQ9Il9lMDMzODkyY2E4YjEzMmI2MzVkZTI3NzRjZGQyNTlmOTE2MDcxMjgyNDIxODkiIElzc3VlSW5zdGFudD0iMjAyMC0xMi0wNVQwMDozMDo0Mi4xODlaIiBWZXJzaW9uPSIyLjAiPjxzYW1sOklzc3VlciBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI+aHR0cHM6Ly9kanVhbmcxLWRldi1lZC5teS5zYWxlc2ZvcmNlLmNvbTwvc2FtbDpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+CjxkczpTaWduZWRJbmZvPgo8ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPgo8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+CjxkczpSZWZlcmVuY2UgVVJJPSIjX2UwMzM4OTJjYThiMTMyYjYzNWRlMjc3NGNkZDI1OWY5MTYwNzEyODI0MjE4OSI+CjxkczpUcmFuc2Zvcm1zPgo8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz4KPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyI+PGVjOkluY2x1c2l2ZU5hbWVzcGFjZXMgeG1sbnM6ZWM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIgUHJlZml4TGlzdD0iZHMgc2FtbCB4cyB4c2kiLz48L2RzOlRyYW5zZm9ybT4KPC9kczpUcmFuc2Zvcm1zPgo8ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz4KPGRzOkRpZ2VzdFZhbHVlPnJNNjMydEFCcDlVWXRkUDRZTmdPZXduMzlpcz08L2RzOkRpZ2VzdFZhbHVlPgo8L2RzOlJlZmVyZW5jZT4KPC9kczpTaWduZWRJbmZvPgo8ZHM6U2lnbmF0dXJlVmFsdWU+CllWL3RvL0hMamRhcWprRk91T3BWaDM2TXFKRzlGUVdVZEtBcXYxbnlNMXhOc2kvTFN0dGNrLzRNejl2Q3VCVXJYSWsxVS9oV2YwTzUKRXNpbzJzU2tKdGUwL2lWcDhTSlRqenAzT3VDdE9nUlNvTTJxVThTdWExS1pvenBXVG0rM3o5U0pIWm1EV2llbXJWZFVwUEVKTnNUMwo4bi80QkFKWWtNNnZWdmNDbm5HVVRHVVNjeURHakV1MFlrQmhnNmJpMGpLczIvNjErMytzb3Juem1nQlREN3JEMUF4VFhLRVh1aW1qCkNPSThnNEhtOHJFOHMwcXVSUkhxZXRXZmk1YVFxQ3NDdGJ2ZmNMVWtaSklIYkxSUjNXZi8zNmNhK25HNDV6TXE2bmhPMlBza0FBZlAKK0x6ejk1dWxDUnVabUxubUNvcHhtSW1GTTBkaERSQ3IyL29iWGc9PQo8L2RzOlNpZ25hdHVyZVZhbHVlPgo8ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlFVWpDQ0F6cWdBd0lCQWdJT0FYVGY1T1NjQUFBQUFGMmFhWnN3RFFZSktvWklodmNOQVFFTEJRQXdkREVNTUFvR0ExVUVBd3dEClUxTlBNUmd3RmdZRFZRUUxEQTh3TUVSdk1EQXdNREF3TUZwd09VVXhGekFWQmdOVkJBb01EbE5oYkdWelptOXlZMlV1WTI5dE1SWXcKRkFZRFZRUUhEQTFUWVc0Z1JuSmhibU5wYzJOdk1Rc3dDUVlEVlFRSURBSkRRVEVNTUFvR0ExVUVCaE1EVlZOQk1CNFhEVEl3TURregpNREUyTkRJek5Gb1hEVEl4TURrek1ERXlNREF3TUZvd2RERU1NQW9HQTFVRUF3d0RVMU5QTVJnd0ZnWURWUVFMREE4d01FUnZNREF3Ck1EQXdNRnB3T1VVeEZ6QVZCZ05WQkFvTURsTmhiR1Z6Wm05eVkyVXVZMjl0TVJZd0ZBWURWUVFIREExVFlXNGdSbkpoYm1OcGMyTnYKTVFzd0NRWURWUVFJREFKRFFURU1NQW9HQTFVRUJoTURWVk5CTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQwpBUUVBcCs0Y1NzV2lPWmdXM2xlMm9iQXpxZldnL081bTJKZkdNdkxWOUM0SU5KSnRqd2RUZkxVaEtkRHl3Q0MwbE1BVGVudW9lelJ5CjRpWHVjMTFsWFdDaGxOODdRSzZ4dDYzcFZtditnUWFXa1ZzK3lWZHcwWkZ2enVDMWtkb2VRVGtLR25qK3o5Wld6eCtrbjE3SUVWa0oKaVZkZnpRWmJHTmtKVVJOMHJoaXRVSm5ZTUJhRkE1a0wybExRU2NBRm5LaDlES2E3RWFEeTR5YnkxYUdlS2MrRXUyWTloZk9HT202agpIYmVFSVdlSm5tU2tZN3lYQXFRSFRZQUxJVXZQa1l0T1EvamVMd1FLVjhqeDRzUmxReklIblRSbTlKNVFhMUxSQ3ZKR0hxQ1ZCV0RzCjIvRDVqdERnZlQ1bVJwS3cxWkdSdXRIbGJJc1hITmZuVkNMZ1B3QkhXUUlEQVFBQm80SGhNSUhlTUIwR0ExVWREZ1FXQkJTVWVvNjgKT2xBN1BKR0ZSLzlGN1hCUGxsQm8rekFQQmdOVkhSTUJBZjhFQlRBREFRSC9NSUdyQmdOVkhTTUVnYU13Z2FDQUZKUjZqcnc2VURzOAprWVZILzBYdGNFK1dVR2o3b1hpa2RqQjBNUXd3Q2dZRFZRUUREQU5UVTA4eEdEQVdCZ05WQkFzTUR6QXdSRzh3TURBd01EQXdXbkE1ClJURVhNQlVHQTFVRUNnd09VMkZzWlhObWIzSmpaUzVqYjIweEZqQVVCZ05WQkFjTURWTmhiaUJHY21GdVkybHpZMjh4Q3pBSkJnTlYKQkFnTUFrTkJNUXd3Q2dZRFZRUUdFd05WVTBHQ0RnRjAzK1RrbkFBQUFBQmRtbW1iTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFBUwpXWFJiVDdGamQyWjlHVWVxajM2UDFqeC9wOEEvdjViZWRaVjk3bHJGZEhHZkk0MEw5UkdIMWVBZkxTQ2VvUnltRVVKUDhOZmtNYkxvCnB5Z1hKUHJIbUJad0JOMDdiUmVIQlNaN0JXekh0ZHJwb1Z6WXEyd2Evdi9PM0VVQUZPL21DSmxMb1RzaGl4L1NxcFBDOGVVR1hNakMKUzNhanZBSWl2a0xzTnUxdkVxaE1sTnZYMUk4RnM1STExNjBjS2NSdmtoVEVjdlBLckU4cUo4cnB4bENUNElQVWhJeUk2WE9hS1FjeQpKbTM3VUN2WVh5SGlGWmdMVXlYRFUyNmkvb2FzMGNxdW5CdjhsNmREL01KMHppb1hBekpqNmF5ZFA3R2sxSmM1QjJLMUxhNWc0Ymh3CmtnQXZMT2lFR3pTMkdKUFlxWG0wUEV3ZStGS2hoL3hhSlZDUjwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1sOlN1YmplY3Q+PHNhbWw6TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6dW5zcGVjaWZpZWQiPmRyZWFtZm9yY2UyMDE0QG11bGVzb2Z0LmNvbTwvc2FtbDpOYW1lSUQ+PHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb25EYXRhIEluUmVzcG9uc2VUbz0iZDNiZTU0NzgtZTBlZi00ZjQwLTljMTgtMzk5YmQyYjRkNDg4IiBOb3RPbk9yQWZ0ZXI9IjIwMjAtMTItMDVUMDA6MzU6NDIuMTg5WiIgUmVjaXBpZW50PSJodHRwOi8vbG9jYWxob3N0OjgwODEvY2FsbGJhY2siLz48L3NhbWw6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWw6U3ViamVjdD48c2FtbDpDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAyMC0xMi0wNVQwMDozMDoxMi4xODlaIiBOb3RPbk9yQWZ0ZXI9IjIwMjAtMTItMDVUMDA6MzU6NDIuMTg5WiI+PHNhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDpBdWRpZW5jZT5odHRwOi8vbG9jYWxob3N0OjgwODE8L3NhbWw6QXVkaWVuY2U+PC9zYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+PC9zYW1sOkNvbmRpdGlvbnM+PHNhbWw6QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDIwLTEyLTA1VDAwOjMwOjQyLjE4OVoiPjxzYW1sOkF1dGhuQ29udGV4dD48c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3Nlczp1bnNwZWNpZmllZDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWw6QXV0aG5Db250ZXh0Pjwvc2FtbDpBdXRoblN0YXRlbWVudD48c2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+PHNhbWw6QXR0cmlidXRlIE5hbWU9InVzZXJJZCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1bnNwZWNpZmllZCI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6YW55VHlwZSI+MDA1bzAwMDAwMDE3RzhhPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9InVzZXJuYW1lIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVuc3BlY2lmaWVkIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czphbnlUeXBlIj5kcmVhbWZvcmNlMjAxNEBtdWxlc29mdC5jb208L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iZW1haWwiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dW5zcGVjaWZpZWQiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOmFueVR5cGUiPmRlamltLmp1YW5nK3NmZGNAbXVsZXNvZnQuY29tPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9ImlzX3BvcnRhbF91c2VyIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVuc3BlY2lmaWVkIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czphbnlUeXBlIj5mYWxzZTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvc2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+PC9zYW1sOkFzc2VydGlvbj48L3NhbWxwOlJlc3BvbnNlPg==";

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
	public AuthnRequest buildAuthenticationRequest(String assertionConsumerServiceUrl, String issuerId, String destinationUrl) {

		// Generate ID
		DateTime issueInstant = new DateTime();
		AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
		AuthnRequest authRequest = authRequestBuilder.buildObject(SAML2_PROTOCOL, "AuthnRequest", "samlp");
		
		// authRequest.setForceAuthn(Boolean.FALSE);
		// authRequest.setIsPassive(Boolean.FALSE);
		// authRequest.setNameIDPolicy(buildNameIDPolicy());
		// authRequest.setRequestedAuthnContext(buildRequestedAuthnContext());
		
		authRequest.setDestination(destinationUrl);
		authRequest.setProviderName("https://saml.salesforce.com");
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
