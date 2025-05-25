import { APP_NAME, APP_URL } from '@repo/constants/app';

export const ChangePasswordSuccessMail = ({ name }: { name: string }) => {
  return `
    <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="x-apple-disable-message-reformatting" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Password Changed Successfully</title>
</head>
<body style="background-color:#efeff1;margin:0;padding:0;">
<div style="max-width:580px;margin:30px auto;background:#fff;padding:30px;">
  <div style="text-align:center;margin-bottom:20px;">
    <img src="${APP_URL}/assets/logo/icon.svg" alt="${APP_NAME}" width="50" height="50" style="display:block;margin:0 auto;" />
  </div>

  <hr style="border:none;border-top:1px solid #9147ff;margin:20px 0;" />

  <h4 style="margin:0 0 16px;">Hi, ${name}</h4>

  <p style="font-size:14px;line-height:1.5;color:#333;margin:16px 0;">
    Your password for <strong>${APP_NAME}</strong> has been successfully changed.
  </p>

  <p style="font-size:14px;line-height:1.5;color:#333;margin:16px 0;">
    If you didn’t make this change, please <a href="${APP_URL}/auth/reset" style="color:#3b82f6;text-decoration:underline;">reset your password</a> immediately and contact support.
  </p>

  <p style="font-size:14px;line-height:1.5;margin:16px 0;">
    Thanks,<br />
    ${APP_NAME} Support Team
  </p>
</div>

<footer style="text-align:center;font-size:14px;color:#706a7b;margin:16px auto;">
  © ${new Date().getFullYear()} ${APP_NAME}, All Rights Reserved.
</footer>
</body>
</html>

`;
};
