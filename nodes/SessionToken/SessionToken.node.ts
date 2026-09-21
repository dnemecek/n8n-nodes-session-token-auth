import type {
	ICredentialDataDecryptedObject,
	IDataObject,
	IExecuteFunctions,
	IHttpRequestHelper,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';

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
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		credentials: [
			{
				name: 'sessionTokenAuth',
				required: true,
			},
		],
		properties: [
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
					throw new NodeOperationError(this.getNode(), `Unknown operation "${operation}"`, {
						itemIndex,
					});
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
					returnData.push({
						json: { error: (error as Error).message },
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
