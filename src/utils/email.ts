import vento from "ventojs";

const STYLES = `
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        line-height: 1.6;
        color: #333;
        max-width: 600px;
        margin: 0 auto;
        padding: 20px;
        background-color: #f4f4f4;
    }
    .email-container {
        background-color: white;
        padding: 30px;
        border-radius: 10px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .header {
        text-align: center;
        padding-bottom: 20px;
        margin-bottom: 30px;
    }
    .header.blue {
        border-bottom: 2px solid #007bff;
    }
    .header.green {
        border-bottom: 2px solid #28a745;
    }
    .header.red {
        border-bottom: 2px solid #dc3545;
    }
    .logo {
        font-size: 24px;
        font-weight: bold;
    }
    .logo.blue {
        color: #007bff;
    }
    .logo.green {
        color: #28a745;
    }
    .logo.red {
        color: #dc3545;
    }
    .verification-code {
        background-color: #f8f9fa;
        padding: 20px;
        text-align: center;
        margin: 20px 0;
        border-radius: 8px;
    }
    .verification-code.blue {
        border: 2px dashed #007bff;
    }
    .verification-code.green {
        border: 2px dashed #28a745;
    }
    .verification-code.red {
        border: 2px dashed #dc3545;
    }
    .code {
        font-family: 'Courier New', monospace;
        font-size: 24px;
        font-weight: bold;
        letter-spacing: 3px;
    }
    .code.blue {
        color: #007bff;
    }
    .code.green {
        color: #28a745;
    }
    .code.red {
        color: #dc3545;
    }
    .footer {
        margin-top: 30px;
        padding-top: 20px;
        border-top: 1px solid #eee;
        font-size: 12px;
        color: #666;
        text-align: center;
    }
    .alert {
        padding: 15px;
        border-radius: 5px;
        margin: 20px 0;
    }
    .alert.warning {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        color: #856404;
    }
    .alert.info {
        background-color: #d1ecf1;
        border: 1px solid #bee5eb;
        color: #0c5460;
    }
    .alert.success {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
    }
    .alert.danger {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
    }
`;

const TEMPLATES = {
  EMAIL_UPDATE_REQUEST: `<!DOCTYPE html>
  <html lang="en">
  <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Email Update Request</title>
      <style>${STYLES}</style>
  </head>
  <body>
      <div class="email-container">
          <div class="header blue">
              <div class="logo blue">{{ companyName || "Your Company" }}</div>
              <h1>Email Address Update Request</h1>
          </div>
          <p>Hello {{ userName || "there" }},</p>
          <p>We received a request to update the email address associated with your account. To complete this change, please use the verification code below:</p>
          <div class="verification-code blue">
              <div>Your verification code is:</div>
              <div class="code blue">{{ codeVerifier }}</div>
          </div>
          <div class="alert warning">
              <strong>Important:</strong> This code will expire in {{ expiry_minutes || "15" }} minutes. If you didn't request this email change, please ignore this message or contact our support team immediately.
          </div>
          <p><strong>Security Information:</strong></p>
          <ul>
              <li>Request time: {{ requestTime || "Just now" }}</li>
              {{ if ipAddress }}
              <li>Request IP: {{ ipAddress }}</li>
              {{ /if }}
              {{ if userAgent }}
              <li>Device: {{ userAgent }}</li>
              {{ /if }}
          </ul>
          <p>If you have any questions or concerns, please don't hesitate to contact our support team.</p>
          <p>Best regards,<br>
          The {{ companyName || "Your Company" }} Team</p>
          <div class="footer">
              <p>This is an automated message. Please do not reply to this email.</p>
              {{ if companyAddress }}
              <p>{{ companyAddress }}</p>
              {{ /if }}
          </div>
      </div>
  </body>
  </html>`,
  EMAIL_VERIFICATION_REQUEST: `<!DOCTYPE html>
  <html lang="en">
  <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Email Verification Request</title>
      <style>${STYLES}</style>
  </head>
  <body>
      <div class="email-container">
          <div class="header green">
              <div class="logo green">{{ companyName || "Your Company" }}</div>
              <h1>Welcome! Please Verify Your Email</h1>
          </div>
          <div class="alert success">
              <strong>Welcome to {{ companyName || "our platform" }}!</strong> We're excited to have you on board.
          </div>
          <p>Hello {{ userName || "there" }},</p>
          <p>Thank you for signing up! To complete your registration and start using your account, please verify your email address using the code below:</p>
          <div class="verification-code green">
              <div>Your verification code is:</div>
              <div class="code green">{{ codeVerifier }}</div>
          </div>
          <div class="alert info">
              <strong>Note:</strong> This verification code will expire in {{ expiry_minutes || "15" }} minutes. Please complete the verification process as soon as possible.
          </div>
          <p><strong>What happens after verification?</strong></p>
          <ul>
              <li>Your account will be fully activated</li>
              <li>You'll receive important updates and notifications</li>
              <li>You can access all features of your account</li>
          </ul>
          <p><strong>Security Information:</strong></p>
          <ul>
              <li>Registration time: {{ requestTime || "Just now" }}</li>
              {{ if ipAddress }}
              <li>Registration IP: {{ ipAddress }}</li>
              {{ /if }}
              {{ if userAgent }}
              <li>Device: {{ userAgent }}</li>
              {{ /if }}
          </ul>
          <p>If you didn't create this account, please ignore this email.</p>
          <p>Welcome aboard!<br>
          The {{ companyName || "Your Company" }} Team</p>
          <div class="footer">
              <p>This is an automated message. Please do not reply to this email.</p>
              {{ if companyAddress }}
              <p>{{ companyAddress }}</p>
              {{ /if }}
          </div>
      </div>
  </body>
  </html>`,
  PASSWORD_RESET_REQUEST: `<!DOCTYPE html>
  <html lang="en">
  <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Password Reset Request</title>
      <style>${STYLES}</style>
  </head>
  <body>
      <div class="email-container">
          <div class="header red">
              <div class="logo red">{{ companyName || "Your Company" }}</div>
              <h1>Password Reset Request</h1>
          </div>
          <p>Hello {{ userName || "there" }},</p>
          <p>We received a request to reset the password for your account. Use the verification code below to proceed with resetting your password:</p>
          <div class="verification-code red">
              <div>Your password reset code is:</div>
              <div class="code red">{{ codeVerifier }}</div>
          </div>
          <div class="alert danger">
              <strong>Important:</strong> This code will expire in {{ expiry_minutes || "15" }} minutes. For your security, please complete the password reset process as soon as possible.
          </div>
          <div class="alert warning">
              <strong>Security Notice:</strong> If you didn't request this password reset, your account may be at risk. Please contact our support team immediately and consider changing your password.
          </div>
          <p><strong>Security Tips:</strong></p>
          <ul>
              <li>Choose a strong, unique password</li>
              <li>Don't reuse passwords from other accounts</li>
              <li>Consider using a password manager</li>
              <li>Enable two-factor authentication if available</li>
          </ul>
          <p><strong>Request Information:</strong></p>
          <ul>
              <li>Request time: {{ requestTime || "Just now" }}</li>
              {{ if ipAddress }}
              <li>Request IP: {{ ipAddress }}</li>
              {{ /if }}
              {{ if userAgent }}
              <li>Device: {{ userAgent }}</li>
              {{ /if }}
          </ul>
          <p>If you have any questions or concerns about this request, please contact our support team immediately.</p>
          <p>Best regards,<br>
          The {{ companyName || "Your Company" }} Team</p>
          <div class="footer">
              <p>This is an automated message. Please do not reply to this email.</p>
              {{ if companyAddress }}
              <p>{{ companyAddress }}</p>
              {{ /if }}
          </div>
      </div>
  </body>
  </html>`,
};

function buildEmailRenderer() {
  const env = vento();
  return (target: keyof typeof TEMPLATES, datum: any) => {
    return env.runStringSync(TEMPLATES[target], datum).content;
  };
}

export const emailRenderer = buildEmailRenderer();
