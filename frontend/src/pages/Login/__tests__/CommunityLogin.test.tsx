import afterLogin from 'AppRoutes/utils';
import { rest, server } from 'mocks-server/server';
import { render, screen, waitFor } from 'tests/test-utils';

import CommunityLogin from '../CommunityLogin';

jest.mock('AppRoutes/utils', () => ({ __esModule: true, default: jest.fn() }));
const endpoint = '*/api/v1/community-oidc';

function configureStatus(enabled: boolean): void {
	server.use(
		rest.get(`${endpoint}/status`, (_, res, ctx) =>
			res(ctx.json({ status: 'success', data: { enabled } })),
		),
	);
}

afterEach(() => {
	window.history.replaceState(null, '', '/');
	jest.clearAllMocks();
});

it('offers OIDC on an enabled installation', async () => {
	configureStatus(true);
	render(<CommunityLogin>Local login</CommunityLogin>);
	await expect(
		screen.findByTestId('community-oidc-login'),
	).resolves.toHaveAttribute('href', '/api/v1/community-oidc/login');
	expect(screen.queryByText('Local login')).not.toBeInTheDocument();
});

it('keeps the normal login on an installation without OIDC', async () => {
	configureStatus(false);
	render(<CommunityLogin>Local login</CommunityLogin>);
	await expect(screen.findByText('Local login')).resolves.toBeInTheDocument();
});

it('exchanges the browser handoff once and clears the marker', async () => {
	configureStatus(true);
	let calls = 0;
	server.use(
		rest.post(`${endpoint}/complete`, (_, res, ctx) => {
			calls += 1;
			return res(
				ctx.json({
					status: 'success',
					data: { accessToken: 'access', refreshToken: 'refresh' },
				}),
			);
		}),
	);
	render(<CommunityLogin>Local login</CommunityLogin>, undefined, {
		initialRoute: '/login#community-oidc',
	});
	await waitFor(() =>
		expect(afterLogin).toHaveBeenCalledWith('access', 'refresh'),
	);
	expect(calls).toBe(1);
	expect(window.location.hash).toBe('');
});

it('lets the user start again after a rejected handoff', async () => {
	configureStatus(true);
	server.use(
		rest.post(`${endpoint}/complete`, (_, res, ctx) => res(ctx.status(403))),
	);
	render(<CommunityLogin>Local login</CommunityLogin>, undefined, {
		initialRoute: '/login#community-oidc',
	});
	await expect(screen.findByRole('alert')).resolves.toHaveTextContent(
		'Sign-in could not be completed.',
	);
	await expect(
		screen.findByTestId('community-oidc-login'),
	).resolves.toBeInTheDocument();
	expect(afterLogin).not.toHaveBeenCalled();
});
