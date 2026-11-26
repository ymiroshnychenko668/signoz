import { useEffect, type ReactNode } from 'react';
import { useMutation, useQuery } from 'react-query';
import { Button, Spin } from 'antd';

import {
	communityLoginURL,
	completeCommunityLogin,
	isCommunityOidcEnabled,
} from './communityOidc';

export default function CommunityLogin({
	children,
}: {
	children: ReactNode;
}): JSX.Element {
	const status = useQuery(['community-oidc-status'], isCommunityOidcEnabled, {
		retry: false,
	});
	const {
		mutate: complete,
		isLoading: completing,
		isError: completionFailed,
	} = useMutation(completeCommunityLogin, { retry: false });

	useEffect(() => {
		if (window.location.hash === '#community-oidc') {
			const url = new URL(window.location.href);
			url.hash = '';
			window.history.replaceState(window.history.state, '', url);
			complete();
		}
	}, [complete]);

	const params = new URLSearchParams(window.location.search);
	if (status.isLoading || completing) {
		return <Spin aria-label="Loading sign-in" />;
	}
	if (status.isError) {
		return (
			<div role="alert">
				Unable to load sign-in options.{' '}
				<button
					type="button"
					onClick={(): void => {
						void status.refetch();
					}}
				>
					Retry
				</button>
			</div>
		);
	}
	if (!status.data || params.get('password') === 'Y') {
		return <>{children}</>;
	}

	return (
		<div className="login-form-container">
			<h2>Sign in to your workspace</h2>
			{(completionFailed || params.has('callbackauthnerr')) && (
				<p role="alert">
					Sign-in could not be completed. Try again or contact your administrator.
				</p>
			)}
			<Button
				type="primary"
				size="large"
				href={communityLoginURL}
				data-testid="community-oidc-login"
				block
			>
				Sign in with Keycloak
			</Button>
		</div>
	);
}
