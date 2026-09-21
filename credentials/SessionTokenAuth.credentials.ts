import type {
	ICredentialDataDecryptedObject,
	ICredentialTestRequest,
	ICredentialType,
	IDataObject,
	IHttpRequestHelper,
	IHttpRequestOptions,
	INodeProperties,
	Icon,
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
 * How n8n drives this (packages/cli/src/credentials-helper.ts, `preAuthentication`):
 * the hook is only ever invoked when the credential type declares a `hidden`
 * property with `typeOptions.expirable: true` AND that property is empty (first
 * use) or a request came back 401 (`credentialsExpired`) or the credential is
 * being tested. The returned object must contain that same property name, or
 * n8n discards the result. That is why `sessionToken` below is declared as a
 * hidden expirable property: without it the login would never run.
 */

function getByPath(obj: IDataObject, path: string): unknown {
	return path
		.split('.')
		.reduce<unknown>((acc, key) => (acc && typeof acc === 'object' ? (acc as IDataObject)[key] : undefined), obj);
}

/**
 * Parses the optional "Extra Login Fields" JSON. n8n hands a `json` property
 * over either as a string (typed in the UI) or already as an object (set via
 * API/import), so both are accepted. Anything that is not a plain object is
 * rejected loudly — silently ignoring a typo here would produce a login
 * request the API rejects with an unhelpful 400.
 */
function parseExtraLoginFields(raw: unknown): IDataObject {
	if (raw === undefined || raw === null || raw === '') return {};
	let value: unknown = raw;
	if (typeof raw === 'string') {
		if (!raw.trim()) return {};
		try {
			value = JSON.parse(raw);
		} catch {
			throw new Error('SessionTokenAuth: "Extra Login Fields" is not valid JSON.');
		}
	}
	if (!value || typeof value !== 'object' || Array.isArray(value)) {
		throw new Error('SessionTokenAuth: "Extra Login Fields" must be a JSON object, e.g. { "LanguageId": "CZ" }.');
	}
	return value as IDataObject;
}

export class SessionTokenAuth implements ICredentialType {
	name = 'sessionTokenAuth';

	displayName = 'Session Token Auth API';

	documentationUrl = 'https://github.com/dnemecek/n8n-nodes-session-token-auth';

	icon: Icon = 'fa:key';

	// Makes this credential appear as a ready-made "Session Token Auth" HTTP Request
	// preset in the node palette (n8n's credential-only-node mechanism).
	httpRequestNode: ICredentialType['httpRequestNode'] = {
		name: 'Session Token Auth',
		docsUrl: 'https://github.com/dnemecek/n8n-nodes-session-token-auth',
		apiBaseUrlPlaceholder: 'https://api.example.com/',
	};

	properties: INodeProperties[] = [
		{
			// The expirable property: n8n runs `preAuthentication` only while this is
			// empty (or after a 401), and stores the returned value here.
			displayName: 'Session Token',
			name: 'sessionToken',
			type: 'hidden',
			typeOptions: { expirable: true },
			default: '',
		},
		{
			// Filled by `preAuthentication` alongside the token (server-confirmed username).
			displayName: 'Resolved Username',
			name: 'resolvedUsername',
			type: 'hidden',
			default: '',
		},
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
			displayName: 'Extra Login Fields (JSON)',
			name: 'extraLoginFields',
			type: 'json',
			default: '',
			placeholder: '{ "LanguageId": "CZ", "DbProfile": "erp", "UseWindowsAuthentication": false }',
			description:
				'Optional JSON object with additional fixed fields the login endpoint requires besides username/password. Sent in the login body (POST) or as query params (GET), where the Username/Password fields overwrite same-named keys. With Body Type "None" they form the JSON body on their own (credentials go via HTTP Basic) and keys named like the Username/Password fields are dropped.',
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
		{
			displayName: 'Test Path',
			name: 'testPath',
			type: 'string',
			default: '',
			placeholder: 'api/me',
			description:
				'Optional path (relative to Base URL) of an authenticated GET endpoint used by the "Test" button. The test always performs the login first; if this is empty the test falls back to a GET on the Login Path, which many APIs reject even though the login itself succeeded.',
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

		const extraLoginFields = parseExtraLoginFields(credentials.extraLoginFields);
		const credentialFields: IDataObject = {
			...extraLoginFields,
			[usernameField]: credentials.username,
			[passwordField]: credentials.password,
		};

		const usesBasicAuthOnLogin = method === 'POST' && bodyType === 'none';
		const extraBodyForBasicLogin: IDataObject = Object.fromEntries(
			Object.entries(extraLoginFields).filter(([key]) => key !== usernameField && key !== passwordField),
		);
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
			// POST + 'none': credentials travel as HTTP Basic, so the body carries only
			// the extra fields (if any). Keys named like the Username/Password fields are
			// removed there — the real credentials go via Basic, never via a stray value
			// from Extra Login Fields.
			body:
				method !== 'POST'
					? undefined
					: bodyType !== 'none'
						? credentialFields
						: Object.keys(extraBodyForBasicLogin).length
							? extraBodyForBasicLogin
							: undefined,
			auth: usesBasicAuthOnLogin
				? { username: String(credentials.username ?? ''), password: String(credentials.password ?? '') }
				: undefined,
			// Content-Type is always explicit on POST. With 'none' there is no body at
			// all, yet some APIs (e.g. a JSON API whose login takes HTTP Basic Auth)
			// still reject a request without Content-Type: application/json (HTTP 415).
			// For 'json' n8n's helper would set it anyway; being explicit costs nothing.
			headers:
				method === 'POST'
					? {
							'Content-Type':
								bodyType === 'form' ? 'application/x-www-form-urlencoded' : 'application/json',
						}
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
	authenticate = async (
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

	// n8n runs `preAuthentication` (the actual login) before this request when the
	// credential is tested, then sends this request with `authenticate` applied.
	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.baseUrl}}',
			url: '={{$credentials.testPath || $credentials.loginPath}}',
			method: 'GET',
		},
	};
}
