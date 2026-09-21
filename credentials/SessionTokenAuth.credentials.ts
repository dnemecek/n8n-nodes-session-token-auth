import type {
	IAuthenticate,
	ICredentialDataDecryptedObject,
	ICredentialTestRequest,
	ICredentialType,
	IDataObject,
	IHttpRequestHelper,
	IHttpRequestOptions,
	INodeProperties,
} from 'n8n-workflow';

/**
 * SessionTokenAuth — n8n Credential Type for APIs shaped like:
 *   POST <loginPath> (username/password) -> response contains a session token
 *   -> subsequent requests send that token in a header (Basic-auth-style or a
 *      plain custom header).
 *
 * Two example shapes this covers:
 *   - A: login returns { userId, userName } -> Authorization: "Basic " +
 *     base64(userName + ":" + userId)
 *   - B: login returns { sessionId } -> a custom header carries the raw token,
 *     e.g. X-Session-Id: <token>
 *
 * n8n calls `preAuthentication` once per credential entry (cached, and re-run
 * automatically when a request using it comes back 401, per credentialsExpired
 * handling in ICredentialsHelper) and merges its returned IDataObject into the
 * decrypted credentials object that `authenticate` then sees.
 */

function getByPath(obj: IDataObject, path: string): unknown {
	return path
		.split('.')
		.reduce<unknown>((acc, key) => (acc && typeof acc === 'object' ? (acc as IDataObject)[key] : undefined), obj);
}

export class SessionTokenAuth implements ICredentialType {
	name = 'sessionTokenAuth';

	displayName = 'Session Token Auth API';

	documentationUrl = 'https://github.com/dnemecek/n8n-nodes-session-token-auth';

	properties: INodeProperties[] = [
		{
			displayName: 'Base URL',
			name: 'baseUrl',
			type: 'string',
			default: '',
			placeholder: 'https://api.example.com/',
			description: 'Trailing slash recommended; Login Path is appended to this.',
			required: true,
		},
		{
			displayName: 'Login Path',
			name: 'loginPath',
			type: 'string',
			default: 'login',
			description: 'Path (relative to Base URL) that performs the login and returns a session token, e.g. "Connect/Login" or "login".',
			required: true,
		},
		{
			displayName: 'Login HTTP Method',
			name: 'loginMethod',
			type: 'options',
			options: [
				{ name: 'POST', value: 'POST' },
				{
					name: 'GET (credentials sent as query params, never as a body)',
					value: 'GET',
				},
			],
			default: 'POST',
			description:
				'GET never attaches a body (many clients/servers/proxies drop or log it) — credentials go in the query string instead.',
		},
		{
			displayName: 'Login Body Type',
			name: 'loginBodyType',
			type: 'options',
			options: [
				{ name: 'JSON', value: 'json' },
				{ name: 'Form-Urlencoded', value: 'form' },
				{
					name: 'None (Basic Auth on POST; ignored on GET — GET always uses query params)',
					value: 'none',
					description: 'On POST, sends HTTP Basic Auth on the login request. Has no effect on GET.',
				},
			],
			default: 'json',
			description: 'Only applies to POST. GET always sends credentials as query params, regardless of this field.',
		},
		{
			displayName: 'Username',
			name: 'username',
			type: 'string',
			default: '',
			required: true,
		},
		{
			displayName: 'Password',
			name: 'password',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
		},
		{
			displayName: 'Username Field (in Login Body)',
			name: 'usernameField',
			type: 'string',
			default: 'username',
			description: 'Key name for the username in the login request body.',
		},
		{
			displayName: 'Password Field (in Login Body)',
			name: 'passwordField',
			type: 'string',
			default: 'password',
			description: 'Key name for the password in the login request body.',
		},
		{
			displayName: 'Token Field (in Login Response)',
			name: 'tokenField',
			type: 'string',
			default: 'token',
			description: 'Dot-path to the session token in the login response JSON, e.g. "userId" or "sessionId".',
			required: true,
		},
		{
			displayName: 'Username Field (in Login Response)',
			name: 'responseUsernameField',
			type: 'string',
			default: '',
			description: 'Optional dot-path to the (possibly server-confirmed) username in the login response, e.g. "userName". Leave empty to reuse the Username you entered above.',
		},
		{
			displayName: 'Header Format',
			name: 'headerFormat',
			type: 'options',
			options: [
				{
					name: 'Basic (base64 of username:token)',
					value: 'basic',
					description: 'Authorization: Basic base64(username:token)',
				},
				{
					name: 'Raw Token',
					value: 'raw',
					description: 'Header value is the token itself, unmodified',
				},
			],
			default: 'basic',
		},
		{
			displayName: 'Header Name',
			name: 'headerName',
			type: 'string',
			default: 'Authorization',
			description: 'Header sent on every authenticated request, e.g. "Authorization" or "X-Session-Id".',
			required: true,
		},
	];

	async preAuthentication(
		this: IHttpRequestHelper,
		credentials: ICredentialDataDecryptedObject,
	): Promise<IDataObject> {
		const baseUrl = String(credentials.baseUrl ?? '').replace(/\/+$/, '');
		if (!/^https:\/\//i.test(baseUrl)) {
			throw new Error(
				`SessionTokenAuth: Base URL must start with "https://" (got "${baseUrl}"). Credentials and the session token are sent over this connection — plain http:// would expose them in transit.`,
			);
		}
		const loginPath = String(credentials.loginPath ?? '').replace(/^\/+/, '');
		const url = `${baseUrl}/${loginPath}`;
		const method = (credentials.loginMethod as 'GET' | 'POST') ?? 'POST';
		const bodyType = String(credentials.loginBodyType ?? 'json');
		const usernameField = String(credentials.usernameField ?? 'username');
		const passwordField = String(credentials.passwordField ?? 'password');

		const credentialFields: IDataObject = {
			[usernameField]: credentials.username,
			[passwordField]: credentials.password,
		};

		const usesBasicAuthOnLogin = method === 'POST' && bodyType === 'none';
		if (usesBasicAuthOnLogin && String(credentials.username ?? '').includes(':')) {
			// RFC 7617 §2: the decoder splits "username:password" on the FIRST colon,
			// so a colon inside the username silently misparses into the wrong pair
			// (e.g. "DOMAIN:user" becomes user="DOMAIN", password="user:<password>").
			throw new Error(
				'SessionTokenAuth: Username cannot contain ":" when using HTTP Basic Auth on the login request (Login Body Type = "None") — per RFC 7617, a colon in the username breaks the username/password split on the server side.',
			);
		}

		// GET never carries a body (many clients/servers/proxies silently drop or log
		// it), so credentials ALWAYS go in the query string for GET, regardless of
		// Login Body Type — that field only makes sense for encoding a POST body.
		// For POST, Login Body Type decides the channel: json/form encode the body;
		// 'none' means the API takes credentials via HTTP Basic auth on the login
		// request itself (the "basic" half of that option's own label) rather than
		// as a request payload — NOT "send nothing", which would silently drop the
		// credentials and was a real bug caught by the previous review round.
		const response = (await this.helpers.httpRequest({
			method,
			url,
			qs: method === 'GET' ? credentialFields : undefined,
			body: method === 'POST' && bodyType !== 'none' ? credentialFields : undefined,
			auth: usesBasicAuthOnLogin
				? { username: String(credentials.username ?? ''), password: String(credentials.password ?? '') }
				: undefined,
			headers:
				method === 'POST' && bodyType === 'form'
					? { 'Content-Type': 'application/x-www-form-urlencoded' }
					: undefined,
			// Response parsing is independent of how the REQUEST body was encoded
			// (loginBodyType describes the request, not what the server replies with).
			// Always request JSON; if the server replies with plain text anyway,
			// n8n's httpRequest helper returns it as a string and the manual
			// JSON.parse fallback below still finds the token.
			json: true,
		})) as IDataObject | string | undefined;

		const responseObject: IDataObject =
			response && typeof response === 'object'
				? response
				: (() => {
						if (typeof response === 'string' && response.trim()) {
							try {
								return JSON.parse(response) as IDataObject;
							} catch {
								// fall through to empty object below
							}
						}
						return {};
					})();

		const tokenField = String(credentials.tokenField ?? 'token');
		const token = getByPath(responseObject, tokenField);
		if (token === undefined || token === null || token === '') {
			const responseKeys = Object.keys(responseObject);
			throw new Error(
				`SessionTokenAuth: login response did not contain a token at path "${tokenField}". ` +
					(responseKeys.length
						? `Response keys: ${responseKeys.join(', ')}`
						: 'Response was empty or not JSON/an object.'),
			);
		}

		const responseUsernameField = String(credentials.responseUsernameField ?? '');
		const resolvedUsername = responseUsernameField
			? (getByPath(responseObject, responseUsernameField) ?? credentials.username)
			: credentials.username;

		return {
			sessionToken: String(token),
			resolvedUsername: String(resolvedUsername ?? ''),
		};
	}

	// Function form (not the declarative IAuthenticateGeneric) — deliberately, so the
	// dynamic HEADER NAME (differs per API — "Authorization" for a Basic-style API,
	// a custom header name for another) is plain JS, not an assumption about whether n8n's
	// declarative-auth engine evaluates expressions inside object KEYS (unconfirmed;
	// its VALUES definitely get resolved, but object keys are a different code path
	// and we should not guess). This form is 100% unambiguous: we get real
	// `credentials` (already merged with preAuthentication's return value) and just
	// set the header ourselves.
	authenticate: IAuthenticate = async (
		credentials: ICredentialDataDecryptedObject,
		requestOptions: IHttpRequestOptions,
	): Promise<IHttpRequestOptions> => {
		const headerName = String(credentials.headerName ?? 'Authorization');
		const headerFormat = String(credentials.headerFormat ?? 'basic');
		const token = String(credentials.sessionToken ?? '');
		const username = String(credentials.resolvedUsername ?? credentials.username ?? '');

		const headerValue =
			headerFormat === 'basic' ? `Basic ${Buffer.from(`${username}:${token}`).toString('base64')}` : token;

		requestOptions.headers = {
			...requestOptions.headers,
			[headerName]: headerValue,
		};
		return requestOptions;
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.baseUrl}}',
			url: '={{$credentials.loginPath}}',
			method: 'POST',
		},
	};
}
