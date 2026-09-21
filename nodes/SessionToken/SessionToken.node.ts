import type {
	ICredentialDataDecryptedObject,
	IDataObject,
	IExecuteFunctions,
	IHttpRequestHelper,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';

import { SessionTokenAuth } from '../../credentials/SessionTokenAuth.credentials';

/**
 * Session Token node.
 *
 * Logs in with a "Session Token Auth API" credential and returns the session
 * token plus the exact header the credential would send, so the token can be
 * used outside the HTTP Request node (Code nodes, tools, third-party nodes that
 * take a raw header). The login is performed on every execution — this node
 * does not cache the token; caching is what the credential itself does when it
 * is used directly on an HTTP Request node.
 *
 * It also makes the package installable through the n8n GUI: n8n rejects
 * community packages that contain credentials but no nodes.
 */
export class SessionToken implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Session Token',
		name: 'sessionToken',
		icon: 'fa:key',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Log in with a Session Token Auth credential and return the session token',
		defaults: {
			name: 'Session Token',
		},
		// String literals instead of `NodeConnectionTypes.Main`: that runtime export
		// only exists in n8n >= 1.85 (March 2025). On older instances it is
		// `undefined`, the constructor throws a TypeError and n8n reports the
		// package as "Class could not be found". 'main' is valid in every version.
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{
				name: 'sessionTokenAuth',
				required: true,
			},
		],
		properties: [
			{
				displayName:
					'The output of this node contains a live session token and the ready-to-use auth header. n8n saves node output in the execution history in plain text, so anyone who can view executions of this workflow can read the token. Prefer using the credential directly on an HTTP Request node; use this node only when you really need the raw token, and consider disabling "Save successful executions" for the workflow.',
				name: 'tokenExposureNotice',
				type: 'notice',
				default: '',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Get Session Token',
						value: 'getToken',
						action: 'Get a session token',
						description:
							'Perform the login and return the session token and the header the credential sends with it',
					},
				],
				default: 'getToken',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const credentialType = new SessionTokenAuth();

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			try {
				const operation = this.getNodeParameter('operation', itemIndex) as string;
				if (operation !== 'getToken') {
					// Plain Error on purpose: n8n wraps it with the node context itself. This
					// file must not `require('n8n-workflow')` at runtime — see the comment
					// on `inputs` below.
					throw new Error(`Unknown operation "${operation}"`);
				}

				const credentials = await this.getCredentials<ICredentialDataDecryptedObject>(
					'sessionTokenAuth',
					itemIndex,
				);

				// Reuse the credential's own login and header logic so this node can never
				// drift from what the HTTP Request node sends.
				const helper: IHttpRequestHelper = { helpers: this.helpers };
				const loginResult = await credentialType.preAuthentication.call(helper, credentials);
				// preAuthentication returns only strings (sessionToken, resolvedUsername), so
				// the merge stays a valid decrypted-credentials object.
				const merged = { ...credentials, ...loginResult } as ICredentialDataDecryptedObject;

				const headerName = String(merged.headerName ?? 'Authorization');
				const authenticated = await credentialType.authenticate(merged, { url: '', headers: {} });
				const headerValue = String((authenticated.headers as IDataObject | undefined)?.[headerName] ?? '');

				const json: IDataObject = {
					sessionToken: String(loginResult.sessionToken ?? ''),
					username: String(loginResult.resolvedUsername ?? ''),
					header: {
						name: headerName,
						value: headerValue,
					},
				};

				returnData.push({ json, pairedItem: { item: itemIndex } });
			} catch (error) {
				if (this.continueOnFail()) {
					// Same top-level shape as a successful item, so downstream expressions
					// like {{ $json.header.value }} never hit an undefined parent.
					returnData.push({
						json: {
							sessionToken: null,
							username: null,
							header: { name: null, value: null },
							error: (error as Error).message,
						},
						pairedItem: { item: itemIndex },
					});
					continue;
				}
				throw error;
			}
		}

		return [returnData];
	}
}
