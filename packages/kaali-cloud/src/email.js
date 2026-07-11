// Resend adapter. In dev with no key, prints the link to the server log so
// you can copy-paste it into a browser — no email loop needed to test.
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

export function verifyEmailTemplate({ link }) {
  return {
    subject: "Verify your Kaali account",
    text: `Welcome to Kaali. Verify your email to activate your account:\n\n${link}\n\nThis link expires in 24 hours.`,
    html: `<p>Welcome to <strong>Kaali</strong>.</p><p>Verify your email to activate your account:</p><p><a href="${link}">${link}</a></p><p style="color:#888">This link expires in 24 hours.</p>`,
  };
}

export function resetEmailTemplate({ link }) {
  return {
    subject: "Reset your Kaali password",
    text: `Reset your Kaali password:\n\n${link}\n\nThis link expires in 1 hour. If you didn't request this, ignore this email.`,
    html: `<p>Reset your <strong>Kaali</strong> password:</p><p><a href="${link}">${link}</a></p><p style="color:#888">This link expires in 1 hour. If you didn't request this, ignore this email.</p>`,
  };
}
