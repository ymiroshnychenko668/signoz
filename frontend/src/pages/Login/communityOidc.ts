import afterLogin from 'AppRoutes/utils';
import axios from 'axios';
import { withBasePath } from 'utils/basePath';

const endpoint = withBasePath('/api/v1/community-oidc');
export const communityLoginURL = `${endpoint}/login`;

export async function isCommunityOidcEnabled(): Promise<boolean> {
	const response = await axios.get<{ data: { enabled: boolean } }>(
		`${endpoint}/status`,
		{
			validateStatus: (status) => status === 200 || status === 404,
		},
	);
	return response.status === 200 && response.data.data.enabled;
}

export async function completeCommunityLogin(): Promise<void> {
	const response = await axios.post<{
		data: { accessToken: string; refreshToken: string };
	}>(`${endpoint}/complete`);
	const { accessToken, refreshToken } = response.data.data;
	if (!accessToken || !refreshToken) {
		throw new Error('Missing session credentials');
	}
	afterLogin(accessToken, refreshToken);
}
