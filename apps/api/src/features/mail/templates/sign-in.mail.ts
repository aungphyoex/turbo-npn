const SignInMail = ({ name }: { name: string }) => {
  return `
   <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html dir="ltr" lang="en">
  <head>
    <meta content="text/html; charset=UTF-8" http-equiv="Content-Type" />
    <meta name="x-apple-disable-message-reformatting" />
  </head>
  <div
    style="
      display: none;
      overflow: hidden;
      line-height: 1px;
      opacity: 0;
      max-height: 0;
      max-width: 0;
    "
  >
    Join Turbo NPN
  </div>
  <body
    style="
      background-color: rgb(255, 255, 255);
      margin-top: auto;
      margin-bottom: auto;
      margin-left: auto;
      margin-right: auto;
      font-family: ui-sans-serif, system-ui, sans-serif, 'Apple Color Emoji',
        'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji';
      padding-left: 0.5rem;
      padding-right: 0.5rem;
    "
  >
    <table
      align="center"
      width="100%"
      border="0"
      cellpadding="0"
      cellspacing="0"
      role="presentation"
      style="
        border-width: 1px;
        border-style: solid;
        border-color: rgb(234, 234, 234);
        border-radius: 0.25rem;
        margin-top: 40px;
        margin-bottom: 40px;
        margin-left: auto;
        margin-right: auto;
        padding: 20px;
        max-width: 465px;
      "
    >
      <tbody>
        <tr style="width: 100%">
          <td>
            <table
              align="center"
              width="100%"
              border="0"
              cellpadding="0"
              cellspacing="0"
              role="presentation"
              style="margin-top: 32px"
            >
              <tbody>
                <tr>
                  <td>
                    <img
                      alt="Vercel"
                      height="37"
                      src="https://react-email-demo-2jmpohtxd-resend.vercel.app/static/vercel-logo.png"
                      style="
                        margin-top: 0px;
                        margin-bottom: 0px;
                        margin-left: auto;
                        margin-right: auto;
                        display: block;
                        outline: none;
                        border: none;
                        text-decoration: none;
                      "
                      width="40"
                    />
                  </td>
                </tr>
              </tbody>
            </table>
            <h1
              style="
                color: rgb(0, 0, 0);
                font-size: 24px;
                font-weight: 400;
                text-align: center;
                padding: 0px;
                margin-top: 30px;
                margin-bottom: 30px;
                margin-left: 0px;
                margin-right: 0px;
              "
            >
              <strong>Turbo NPN</strong>
            </h1>
            <p
              style="
                color: rgb(0, 0, 0);
                font-size: 14px;
                line-height: 24px;
                margin: 16px 0;
              "
            >
              Hello, ${name}
            </p>
            <p
              style="
                color: rgb(0, 0, 0);
                font-size: 14px;
                line-height: 24px;
                margin: 16px 0;
              "
            >
              Turbo NPN send your sign in notification email
            </p>
            <div style="display: flex;justify-content: center; align-items: center;">
              <p
                style="
                  background-color: rgb(0, 0, 0);
                  border-radius: 0.25rem;
                  color: rgb(255, 255, 255);
                  font-size: 12px;
                  font-weight: 600;
                  text-align: center;
                  padding: 0.75rem 1.25rem;
                  line-height: 100%;
                  text-decoration: none;
                  display: inline-block;
                  width: 100%;
                "
              >
                New Sign In Detected
              </p>
            </div>
            <hr
              style="
                border-width: 1px;
                border-style: solid;
                border-color: rgb(234, 234, 234);
                margin-top: 26px;
                margin-bottom: 26px;
                margin-left: 0px;
                margin-right: 0px;
                width: 100%;
                border: none;
                border-top: 1px solid #eaeaea;
              "
            />
            <p
              style="
                color: rgb(102, 102, 102);
                font-size: 12px;
                line-height: 24px;
                margin: 16px 0;
                text-align: center;
              "
            >
              Turbo NPN is a free and open source prodcut
            </p>
          </td>
        </tr>
      </tbody>
    </table>
  </body>
</html>
`;
};

export default SignInMail;
