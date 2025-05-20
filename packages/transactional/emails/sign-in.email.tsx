import { Link, Text } from '@react-email/components';
import EmailLayout from '@repo/transactional/email-layout';

interface SignInEmailProps {
  username?: string;
  loginTime: Date;
  location?: string;
  ipAddress?: string;
}

const logoUrl = 'http://localhost:3000/assets/logo/icon.svg';
const appTitle = 'Turborepo';

export const SignInEmail = ({
  username = 'there',
  loginTime,
  location,
  ipAddress,
}: SignInEmailProps) => {
  const formattedDate = new Intl.DateTimeFormat('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(loginTime);

  return (
    <EmailLayout username={username} preview={'SignIn email'}>
      <Text className="text-start text-[14px] leading-[1.5] text-[#333333]">
        This is a confirmation that you successfully signed in to your{' '}
        {appTitle} account.
      </Text>
      <Text className="text-start text-[14px] leading-[1.5] text-[#333333]">
        <strong>Time:</strong> {formattedDate}
        <br />
        {location && (
          <>
            <strong>Location:</strong> {location}
            <br />
          </>
        )}
        {ipAddress && (
          <>
            <strong>IP Address:</strong> {ipAddress}
          </>
        )}
      </Text>

      <Text className="text-start text-[14px] leading-[1.5] text-[#333333]">
        If this wasn't you, please{' '}
        <Link
          href="https://your-app/reset-password"
          className="text-blue-500 underline"
        >
          reset your password
        </Link>{' '}
        immediately and contact support.
      </Text>
    </EmailLayout>
  );
};

SignInEmail.PreviewProps = {
  username: 'alanturing',
  loginTime: new Date(),
  location: 'San Francisco, CA',
  ipAddress: '192.168.1.1',
} as SignInEmailProps;

export default SignInEmail;
