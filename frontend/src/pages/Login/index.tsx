import AuthPageContainer from 'components/AuthPageContainer';
import LoginContainer from 'container/Login';

import CommunityLogin from './CommunityLogin';

import './Login.styles.scss';

function Login(): JSX.Element {
	return (
		<AuthPageContainer>
			<div className="auth-form-card">
				<CommunityLogin>
					<LoginContainer />
				</CommunityLogin>
			</div>
		</AuthPageContainer>
	);
}

export default Login;
