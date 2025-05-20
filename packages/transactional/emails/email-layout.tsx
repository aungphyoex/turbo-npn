import {
  Body,
  Column,
  Container,
  Head,
  Heading,
  Html,
  Img,
  Preview,
  Row,
  Section,
  Tailwind,
  Text,
} from '@react-email/components';

interface EmailLayoutProps {
  username?: string;
  updatedDate?: Date;
}

const baseUrl = 'http://localhost:3000';
const logoUrl = 'http://localhost:3000/assets/logo/icon.svg';
const appTitle = 'Turborepo';

export const EmailLayout = ({
  children,
  username,
  preview,
}: {
  children: React.ReactNode;
  username: string;
  preview: string;
}) => {
  return (
    <Html>
      <Head />
      <Tailwind>
        <Body className="bg-[#efeef1] font-mono">
          <Preview>{preview}</Preview>
          <Container className="max-w-[580px] mx-auto my-[30px] bg-white">
            <Section className="p-[30px] flex items-center justify-center">
              <Img
                src={logoUrl}
                alt="Twitch"
                className="mx-auto w-[50px] h-[50px]"
                width={114}
              />
            </Section>

            <Section style={sectionsBorders}>
              <Row>
                <Column style={sectionBorder} />
                <Column style={sectionCenter} />
                <Column style={sectionBorder} />
              </Row>
            </Section>

            <Section className="px-5 py-2.5">
              <Heading as="h4" className="leading-[1.5]">
                Hi, {username}
              </Heading>
              <Section className="my-3">{children}</Section>
              <Text className="leading-[1.5]">
                Thanks,
                <br />
                {appTitle} Support Team
              </Text>
            </Section>
          </Container>

          <Section className="max-w-[580px] mx-auto">
            <Row>
              <Text className="text-center text-[#706a7b]">
                © {new Date().getFullYear()} {appTitle}, All Rights Reserved.
              </Text>
            </Row>
          </Section>
        </Body>
      </Tailwind>
    </Html>
  );
};

EmailLayout.PreviewProps = {
  username: 'alanturing',
  updatedDate: new Date('June 23, 2022 4:06:00 pm UTC'),
  preview: 'Reset Password',
} as EmailLayoutProps;

const sectionsBorders = {
  width: '100%',
};
const sectionBorder = {
  borderBottom: '1px solid rgb(238,238,238)',
  width: '249px',
};
const sectionCenter = {
  borderBottom: '1px solid rgb(145,71,255)',
  width: '102px',
};

export default EmailLayout;
