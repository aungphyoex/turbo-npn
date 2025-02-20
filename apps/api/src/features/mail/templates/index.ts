const EmailTemplate = ({
  name = '',
  action = 'sign in',
  timestamp = new Date().toLocaleString(),
  location = 'Unknown',
  device = 'Unknown Device',
  ipAddress = 'Unknown IP',
}) => {
  return `
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html dir="ltr" lang="en">
  <head>
    <meta content="text/html; charset=UTF-8" http-equiv="Content-Type" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="x-apple-disable-message-reformatting" />
  </head>
  <div style="display: none; overflow: hidden; line-height: 1px; opacity: 0; max-height: 0; max-width: 0;">
    Security Alert - New ${action} detected for your Turbo NPN account
  </div>
  <body style="
    background-color: #f5f5f5;
    margin: 0 auto;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    padding: 1rem;
  ">
    <table align="center" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="
      background-color: #ffffff;
      border: 1px solid #eaeaea;
      border-radius: 8px;
      margin: 40px auto;
      padding: 30px;
      max-width: 520px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    ">
      <tbody>
        <tr style="width: 100%">
          <td>
            <table align="center" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation">
              <tbody>
                <tr>
                  <td>
                    <img
                      alt="Turbo NPN Logo"
                      height="45"
                      src="https://your-logo-url.com/logo.png"
                      style="
                        margin: 0 auto;
                        display: block;
                        outline: none;
                        border: none;
                        text-decoration: none;
                      "
                      width="48"
                    />
                  </td>
                </tr>
              </tbody>
            </table>
            
            <h1 style="
              color: #000000;
              font-size: 24px;
              font-weight: 600;
              text-align: center;
              margin: 30px 0;
            ">
              Security Alert
            </h1>

            <p style="
              color: #333333;
              font-size: 16px;
              line-height: 24px;
              margin: 16px 0;
            ">
              Hello ${name},
            </p>

            <p style="
              color: #333333;
              font-size: 16px;
              line-height: 24px;
              margin: 16px 0;
            ">
              We detected a new ${action} to your Turbo NPN account. Here are the details:
            </p>

            <div style="
              background-color: #f8f9fa;
              border-radius: 8px;
              padding: 20px;
              margin: 24px 0;
            ">
              <table width="100%" cellpadding="0" cellspacing="0" style="margin: 12px 0;">
                <tr>
                  <td style="color: #666666; font-size: 14px; padding: 8px 0;">Time:</td>
                  <td style="color: #333333; font-size: 14px; text-align: right;">${timestamp}</td>
                </tr>
                <tr>
                  <td style="color: #666666; font-size: 14px; padding: 8px 0;">Location:</td>
                  <td style="color: #333333; font-size: 14px; text-align: right;">${location}</td>
                </tr>
                <tr>
                  <td style="color: #666666; font-size: 14px; padding: 8px 0;">Device:</td>
                  <td style="color: #333333; font-size: 14px; text-align: right;">${device}</td>
                </tr>
                <tr>
                  <td style="color: #666666; font-size: 14px; padding: 8px 0;">IP Address:</td>
                  <td style="color: #333333; font-size: 14px; text-align: right;">${ipAddress}</td>
                </tr>
              </table>
            </div>

            <div style="text-align: center; margin: 32px 0;">
              <a href="https://turbo-npn.com/security-settings" style="
                background-color: #000000;
                border-radius: 6px;
                color: #ffffff;
                font-size: 14px;
                font-weight: 600;
                text-align: center;
                padding: 12px 24px;
                text-decoration: none;
                display: inline-block;
              ">
                Review Security Settings
              </a>
            </div>

            <p style="
              color: #666666;
              font-size: 14px;
              line-height: 24px;
              margin: 24px 0;
            ">
              If you don't recognize this activity, please <a href="https://turbo-npn.com/support" style="color: #000000; text-decoration: underline;">contact our support team</a> immediately and change your password.
            </p>

            <hr style="
              border: none;
              border-top: 1px solid #eaeaea;
              margin: 26px 0;
              width: 100%;
            " />

            <div style="text-align: center;">
              <p style="
                color: #666666;
                font-size: 12px;
                line-height: 24px;
                margin: 16px 0;
              ">
                Turbo NPN - Secure, Fast, Reliable
              </p>
              
              <div style="margin: 20px 0;">
                <a href="https://twitter.com/turbonpn" style="text-decoration: none; margin: 0 8px;">
                  <img src="https://your-assets.com/twitter.png" alt="Twitter" width="20" height="20" />
                </a>
                <a href="https://facebook.com/turbonpn" style="text-decoration: none; margin: 0 8px;">
                  <img src="https://your-assets.com/facebook.png" alt="Facebook" width="20" height="20" />
                </a>
                <a href="https://linkedin.com/company/turbonpn" style="text-decoration: none; margin: 0 8px;">
                  <img src="https://your-assets.com/linkedin.png" alt="LinkedIn" width="20" height="20" />
                </a>
              </div>

              <p style="
                color: #666666;
                font-size: 12px;
                line-height: 24px;
              ">
                © 2025 Turbo NPN. All rights reserved.
              </p>

              <p style="
                color: #666666;
                font-size: 12px;
                line-height: 24px;
              ">
                <a href="https://turbo-npn.com/privacy" style="color: #666666; text-decoration: underline;">Privacy Policy</a> •
                <a href="https://turbo-npn.com/terms" style="color: #666666; text-decoration: underline;">Terms of Service</a> •
                <a href="https://turbo-npn.com/unsubscribe" style="color: #666666; text-decoration: underline;">Unsubscribe</a>
              </p>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
  </body>
</html>
`;
};

export default EmailTemplate;
