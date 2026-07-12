// Resend adapter + branded transactional email templates.
// Email HTML has to be old-school (tables, inline styles) to survive Gmail /
// Outlook / iOS Mail / Apple Mail. No <style> block, no external CSS.
const FROM = () => process.env.EMAIL_FROM || "Kaali <noreply@kaali.io>";

export async function sendEmail({ to, subject, html, text }) {
  const key = process.env.RESEND_API_KEY;
  if (!key) {
    console.log(`[email:dev] TO=${to}  SUBJECT=${subject}`);
    console.log(`[email:dev] ${text || html?.replace(/<[^>]+>/g, "")}`);
    return { dev: true };
  }
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "authorization": `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify({ from: FROM(), to, subject, html, text }),
  });
  if (!res.ok) throw new Error(`resend ${res.status}: ${await res.text()}`);
  return await res.json();
}

// --- Branded email shell -----------------------------------------------------
// One layout, three templates below fill in {preheader, heading, body, ctaText, ctaHref, footer}.
function emailShell({ preheader, heading, body, ctaText, ctaHref, footer }) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>${heading}</title></head>
<body style="margin:0;padding:0;background:#0a0c10;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;color:#e6edf3;">
<div style="display:none;overflow:hidden;line-height:1;opacity:0;max-height:0;max-width:0;color:transparent">${preheader}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#0a0c10;padding:40px 12px">
  <tr><td align="center">
    <table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;width:100%;background:linear-gradient(180deg,#11151c 0%,#161b24 100%);border:1px solid #222a36;border-radius:16px;overflow:hidden">
      <tr><td style="padding:32px 40px 8px">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0">
          <tr>
            <td style="width:34px">
              <div style="width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,#5eead4,#38bdf8);text-align:center;line-height:34px;color:#04201c;font-weight:700;font-size:18px">॥</div>
            </td>
            <td style="padding-left:12px;font-weight:700;font-size:17px;letter-spacing:.2px;color:#e6edf3">Kaali</td>
          </tr>
        </table>
      </td></tr>
      <tr><td style="padding:24px 40px 8px">
        <h1 style="margin:0 0 12px;font-size:24px;line-height:1.2;letter-spacing:-.01em;color:#e6edf3;font-weight:700">${heading}</h1>
        <div style="font-size:15px;line-height:1.6;color:#c1cad4">${body}</div>
      </td></tr>
      <tr><td style="padding:24px 40px 8px">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
          <td style="border-radius:10px;background:linear-gradient(135deg,#5eead4,#38bdf8)">
            <a href="${ctaHref}" style="display:inline-block;padding:12px 22px;color:#04201c;font-weight:600;font-size:15px;text-decoration:none;border-radius:10px">${ctaText} &rarr;</a>
          </td>
        </tr></table>
      </td></tr>
      <tr><td style="padding:16px 40px 8px">
        <div style="font-size:12.5px;color:#8b97a6;line-height:1.55">Or paste this URL into your browser:<br>
          <a href="${ctaHref}" style="color:#38bdf8;text-decoration:none;word-break:break-all">${ctaHref}</a>
        </div>
      </td></tr>
      <tr><td style="padding:24px 40px 32px">
        <div style="border-top:1px solid #222a36;padding-top:16px;font-size:12px;color:#8b97a6;line-height:1.55">${footer}</div>
      </td></tr>
    </table>
    <div style="max-width:560px;margin:14px auto 0;font-size:11.5px;color:#5b6674;line-height:1.5;text-align:center">
      Kaali &middot; Starvox Labs Pvt Ltd, Mumbai, India &middot;
      <a href="https://kaali.io/privacy.html" style="color:#5b6674;text-decoration:underline">Privacy</a> &middot;
      <a href="https://kaali.io/terms.html" style="color:#5b6674;text-decoration:underline">Terms</a>
    </div>
  </td></tr>
</table>
</body></html>`;
}

// --- Templates ---------------------------------------------------------------
export function verifyEmailTemplate({ link }) {
  return {
    subject: "Verify your Kaali account",
    text: `Welcome to Kaali.\n\nVerify your email to activate your account:\n${link}\n\nThis link expires in 24 hours. If you didn't sign up, you can ignore this message.`,
    html: emailShell({
      preheader: "Confirm your email to finish setting up Kaali.",
      heading: "Verify your email",
      body: "Welcome. One click and you're in — this confirms it's really you and activates your account.",
      ctaText: "Verify email",
      ctaHref: link,
      footer: "Link expires in 24 hours. If you didn't create a Kaali account, ignore this email — nothing happens.",
    }),
  };
}

export function resetEmailTemplate({ link }) {
  return {
    subject: "Reset your Kaali password",
    text: `Reset your Kaali password:\n${link}\n\nThis link expires in 1 hour. If you didn't request this, ignore this email — your password is unchanged.`,
    html: emailShell({
      preheader: "Reset your Kaali password.",
      heading: "Reset your password",
      body: "Tap the button below to choose a new password. For your security, this link only works once.",
      ctaText: "Reset password",
      ctaHref: link,
      footer: "Link expires in 1 hour. If you didn't request a reset, ignore this email — your password stays the same.",
    }),
  };
}

export function welcomeEmailTemplate({ dashboardUrl }) {
  return {
    subject: "Welcome to Kaali",
    text: `Your Kaali account is ready.\n\nOpen your dashboard: ${dashboardUrl}\n\nStart by creating an API key, then wire the CLI or vigil-guard into your app.`,
    html: emailShell({
      preheader: "Your Kaali account is ready.",
      heading: "You're in.",
      body: "Your Kaali account is ready. Create an API key from the dashboard, then wire the CLI or the runtime guard into your app — Kaali starts watching the moment you do.",
      ctaText: "Open dashboard",
      ctaHref: dashboardUrl,
      footer: "Questions? Reply to this email or write to hello@kaali.io.",
    }),
  };
}
