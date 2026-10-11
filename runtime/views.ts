import qrcode from 'qrcode-generator';
import type { Realm } from './store.js';

export type Locale = 'pt-BR' | 'en';

const T = {
  'pt-BR': {
    signIn: 'Entrar', email: 'E-mail', password: 'Senha', forgot: 'Esqueci minha senha', or: 'ou',
    withGoogle: 'Entrar com Google', withFacebook: 'Entrar com Facebook', continue: 'Continuar', cancel: 'Cancelar',
    mfaTitle: 'Verificação em duas etapas', mfaHelp: 'Digite o código de 6 dígitos do aplicativo autenticador, ou um código de recuperação.',
    code: 'Código', enrollTitle: 'Ative a verificação em duas etapas',
    enrollHelp: 'Sua organização exige um segundo fator. Escaneie o QR code com um aplicativo autenticador (Google Authenticator, Microsoft Authenticator, 1Password…) e digite o código gerado.',
    manualKey: 'Ou digite a chave', recoveryTitle: 'Guarde seus códigos de recuperação',
    recoveryHelp: 'Cada código funciona uma vez, se você perder o aparelho. Guarde em lugar seguro: eles não serão mostrados de novo.',
    consentTitle: 'Autorizar acesso', consentHelp: 'quer acessar sua conta com estas permissões:', allow: 'Autorizar', deny: 'Recusar',
    forgotTitle: 'Redefinir a senha', forgotHelp: 'Informe seu e-mail. Se ele tiver acesso, enviaremos um link para criar uma senha nova.',
    sendLink: 'Enviar link', forgotSent: 'Se o e-mail tiver acesso, o link chegará em alguns minutos. Ele vale por 1 hora.',
    newPassword: 'Nova senha', confirmPassword: 'Repita a nova senha', setPassword: 'Salvar senha',
    inviteTitle: 'Crie sua senha', resetTitle: 'Escolha uma nova senha', passwordSaved: 'Senha salva. Você já pode entrar.',
    backToApp: 'Voltar para o aplicativo', linkExpired: 'Este link expirou ou já foi usado. Peça um novo.',
    invalidLogin: 'E-mail ou senha incorretos.', tooMany: 'Muitas tentativas. Aguarde alguns minutos e tente de novo.',
    invalidCode: 'Código inválido.', mismatch: 'As senhas não conferem.', tooShort: 'A senha precisa ter pelo menos 8 caracteres.',
    noAccount: 'Não encontramos uma conta liberada para este login. Fale com quem administra o seu acesso.',
    accountTitle: 'Minha conta', currentPassword: 'Senha atual', changePassword: 'Trocar senha',
    mfaOn: 'A verificação em duas etapas está ligada.', mfaOff: 'A verificação em duas etapas está desligada.',
    enableMfa: 'Ligar verificação em duas etapas', disableMfa: 'Desligar verificação em duas etapas', newRecovery: 'Gerar novos códigos de recuperação',
    mfaRequiredByRealm: 'Sua organização exige a verificação em duas etapas: ela não pode ser desligada.',
    done: 'Pronto.', accountHelp: 'Por segurança, cada alteração pede a sua senha atual.',
    errorTitle: 'Não foi possível continuar', logoutTitle: 'Sair', logoutHelp: 'Deseja sair da sua conta?', logout: 'Sair', loggedOut: 'Você saiu da sua conta.',
    scopes: { openid: 'Saber quem você é', email: 'Ver seu e-mail', profile: 'Ver seu nome', offline_access: 'Manter você conectado' } as Record<string, string>,
    deniedByApp: 'O aplicativo não liberou o seu acesso',
    notNow: 'Agora não', graceUntil: 'Você pode adiar até',
  },
  en: {
    signIn: 'Sign in', email: 'Email', password: 'Password', forgot: 'Forgot password', or: 'or',
    withGoogle: 'Sign in with Google', withFacebook: 'Sign in with Facebook', continue: 'Continue', cancel: 'Cancel',
    mfaTitle: 'Two-step verification', mfaHelp: 'Enter the 6-digit code from your authenticator app, or a recovery code.',
    code: 'Code', enrollTitle: 'Turn on two-step verification',
    enrollHelp: 'Your organization requires a second factor. Scan the QR code with an authenticator app and enter the generated code.',
    manualKey: 'Or type the key', recoveryTitle: 'Save your recovery codes',
    recoveryHelp: 'Each code works once if you lose your device. Keep them safe: they will not be shown again.',
    consentTitle: 'Authorize access', consentHelp: 'wants to access your account with these permissions:', allow: 'Allow', deny: 'Deny',
    forgotTitle: 'Reset password', forgotHelp: 'Enter your email. If it has access, we will send a link to set a new password.',
    sendLink: 'Send link', forgotSent: 'If the email has access, the link will arrive in a few minutes. It is valid for 1 hour.',
    newPassword: 'New password', confirmPassword: 'Repeat the new password', setPassword: 'Save password',
    inviteTitle: 'Create your password', resetTitle: 'Choose a new password', passwordSaved: 'Password saved. You can sign in now.',
    backToApp: 'Back to the application', linkExpired: 'This link expired or was already used. Ask for a new one.',
    invalidLogin: 'Wrong email or password.', tooMany: 'Too many attempts. Wait a few minutes and try again.',
    invalidCode: 'Invalid code.', mismatch: 'The passwords do not match.', tooShort: 'The password must have at least 8 characters.',
    noAccount: 'We could not find an account enabled for this sign-in. Contact your administrator.',
    accountTitle: 'My account', currentPassword: 'Current password', changePassword: 'Change password',
    mfaOn: 'Two-step verification is on.', mfaOff: 'Two-step verification is off.',
    enableMfa: 'Turn on two-step verification', disableMfa: 'Turn off two-step verification', newRecovery: 'Generate new recovery codes',
    mfaRequiredByRealm: 'Your organization requires two-step verification: it cannot be turned off.',
    done: 'Done.', accountHelp: 'For your security, every change asks for your current password.',
    errorTitle: 'Something went wrong', logoutTitle: 'Sign out', logoutHelp: 'Do you want to sign out?', logout: 'Sign out', loggedOut: 'You are signed out.',
    scopes: { openid: 'Know who you are', email: 'See your email', profile: 'See your name', offline_access: 'Keep you signed in' } as Record<string, string>,
    deniedByApp: 'The application did not allow your access',
    notNow: 'Not now', graceUntil: 'You can postpone until',
  },
};
export type Strings = (typeof T)['en'];
export const strings = (locale: Locale): Strings => T[locale] as Strings;

export const esc = (s: unknown) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

const safeColor = (c?: string) => (c && /^#[0-9a-fA-F]{3,8}$/.test(c) ? c : '#2563eb');
const safeUrl = (u?: string) => (u && /^https:\/\/[^\s"'<>]+$/.test(u) ? u : '');

export interface PageOptions { realm: Pick<Realm, 'displayName' | 'branding'> | null; locale: Locale; title: string; body: string; status?: number }

/** One accessible page: no scripts at all (strict CSP), realm color and logo. */
export function page({ realm, locale, title, body }: PageOptions) {
  const color = safeColor(realm?.branding.color);
  const logo = safeUrl(realm?.branding.logoUrl);
  return `<!doctype html>
<html lang="${locale}">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<title>${esc(title)}${realm ? ` · ${esc(realm.displayName)}` : ''}</title>
<style>
:root{--brand:${color};--bg:#f5f6f8;--fg:#1f2933;--muted:#5f6b7a;--card:#fff;--line:#d9dee5;--err:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--fg:#e8ebef;--muted:#a3adb9;--card:#1a1f25;--line:#323a44;--err:#ff8a7a}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:16px}
main{width:100%;max-width:400px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:28px}
header{text-align:center;margin-bottom:20px}header img{max-height:56px;max-width:200px}header p{margin:6px 0 0;color:var(--muted);font-weight:600}
h1{font-size:1.35rem;margin:0 0 12px}p{margin:0 0 14px}.muted{color:var(--muted);font-size:.93rem}
label{display:block;font-weight:600;margin:12px 0 4px}input{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:10px;font:inherit;background:transparent;color:inherit}
input:focus,button:focus,a:focus{outline:3px solid color-mix(in srgb,var(--brand) 45%,transparent);outline-offset:1px}
button,.btn{display:block;width:100%;margin-top:16px;padding:12px;border:0;border-radius:10px;background:var(--brand);color:#fff;font:inherit;font-weight:700;text-align:center;text-decoration:none;cursor:pointer}
.secondary{background:transparent;color:var(--fg);border:1px solid var(--line)}
.err{color:var(--err);font-weight:600}.sep{text-align:center;color:var(--muted);margin:16px 0 0}
.links{text-align:center;margin-top:16px}.links a{color:var(--brand)}
.qr{display:grid;place-items:center;background:#fff;border-radius:10px;padding:8px}.qr svg{width:200px;height:200px}
code{font-size:1rem;letter-spacing:.04em;word-break:break-all}ul.codes{columns:2;padding-left:20px;font-family:ui-monospace,monospace}
section+section{border-top:1px solid var(--line);margin-top:22px;padding-top:6px}
</style>
</head>
<body>
<main>
<header>${logo ? `<img src="${esc(logo)}" alt="${esc(realm?.displayName)}">` : ''}${realm ? `<p>${esc(realm.displayName)}</p>` : ''}</header>
${body}
</main>
</body>
</html>`;
}

const csrfField = (csrf: string) => `<input type="hidden" name="_csrf" value="${esc(csrf)}">`;
const errorLine = (error?: string) => (error ? `<p class="err" role="alert">${esc(error)}</p>` : '');

export function loginForm(t: Strings, o: { action: string; csrf: string; email?: string; error?: string; forgotUrl: string; social: { provider: string; url: string }[] }) {
  return `<h1>${esc(t.signIn)}</h1>${errorLine(o.error)}
<form method="post" action="${esc(o.action)}">${csrfField(o.csrf)}
<label for="email">${esc(t.email)}</label><input id="email" name="email" type="email" autocomplete="username" required autofocus value="${esc(o.email)}">
<label for="password">${esc(t.password)}</label><input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">${esc(t.signIn)}</button></form>
${o.social.length ? `<p class="sep">${esc(t.or)}</p>${o.social.map((s) => `<a class="btn secondary" href="${esc(s.url)}">${esc(s.provider === 'google' ? t.withGoogle : t.withFacebook)}</a>`).join('')}` : ''}
<p class="links"><a href="${esc(o.forgotUrl)}">${esc(t.forgot)}</a></p>`;
}

export function mfaForm(t: Strings, o: { action: string; csrf: string; error?: string }) {
  return `<h1>${esc(t.mfaTitle)}</h1><p class="muted">${esc(t.mfaHelp)}</p>${errorLine(o.error)}
<form method="post" action="${esc(o.action)}">${csrfField(o.csrf)}
<label for="code">${esc(t.code)}</label><input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus maxlength="11">
<button type="submit">${esc(t.continue)}</button></form>`;
}

export function qrSvg(text: string) {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  return qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
}

export function enrollForm(t: Strings, o: { action: string; csrf: string; uri: string; secret: string; error?: string; help?: string; skip?: { action: string; until: string } }) {
  return `<h1>${esc(t.enrollTitle)}</h1><p class="muted">${esc(o.help ?? t.enrollHelp)}</p>${errorLine(o.error)}
<div class="qr" aria-hidden="true">${qrSvg(o.uri)}</div>
<p class="muted">${esc(t.manualKey)}: <code>${esc(o.secret)}</code></p>
<form method="post" action="${esc(o.action)}">${csrfField(o.csrf)}
<label for="code">${esc(t.code)}</label><input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required maxlength="6">
<button type="submit">${esc(t.continue)}</button></form>
${o.skip ? `<form method="post" action="${esc(o.skip.action)}">${csrfField(o.csrf)}<button type="submit" class="secondary">${esc(t.notNow)}</button></form><p class="muted">${esc(t.graceUntil)} ${esc(new Date(o.skip.until).toLocaleDateString(t === T['pt-BR'] ? 'pt-BR' : 'en'))}</p>` : ''}`;
}

export function recoveryCodes(t: Strings, o: { codes: string[]; action?: string; csrf?: string; link?: { href: string; label: string } }) {
  return `<h1>${esc(t.recoveryTitle)}</h1><p class="muted">${esc(t.recoveryHelp)}</p>
<ul class="codes">${o.codes.map((c) => `<li><code>${esc(c)}</code></li>`).join('')}</ul>
${o.action ? `<form method="post" action="${esc(o.action)}">${csrfField(o.csrf ?? '')}<button type="submit">${esc(t.continue)}</button></form>` : ''}
${o.link ? `<a class="btn" href="${esc(o.link.href)}">${esc(o.link.label)}</a>` : ''}`;
}

export function consentForm(t: Strings, o: { action: string; abort: string; csrf: string; clientName: string; scopes: string[] }) {
  return `<h1>${esc(t.consentTitle)}</h1><p><strong>${esc(o.clientName)}</strong> ${esc(t.consentHelp)}</p>
<ul>${o.scopes.map((s) => `<li>${esc(t.scopes[s] ?? s)}</li>`).join('')}</ul>
<form method="post" action="${esc(o.action)}">${csrfField(o.csrf)}<button type="submit">${esc(t.allow)}</button></form>
<a class="btn secondary" href="${esc(o.abort)}">${esc(t.deny)}</a>`;
}

export function forgotForm(t: Strings, o: { action: string; csrf: string; sent?: boolean; error?: string }) {
  if (o.sent) return `<h1>${esc(t.forgotTitle)}</h1><p role="status">${esc(t.forgotSent)}</p>`;
  return `<h1>${esc(t.forgotTitle)}</h1><p class="muted">${esc(t.forgotHelp)}</p>${errorLine(o.error)}
<form method="post" action="${esc(o.action)}">${csrfField(o.csrf)}
<label for="email">${esc(t.email)}</label><input id="email" name="email" type="email" autocomplete="username" required autofocus>
<button type="submit">${esc(t.sendLink)}</button></form>`;
}

export function setPasswordForm(t: Strings, o: { action: string; csrf: string; invite: boolean; email: string; error?: string }) {
  return `<h1>${esc(o.invite ? t.inviteTitle : t.resetTitle)}</h1><p class="muted">${esc(o.email)}</p>${errorLine(o.error)}
<form method="post" action="${esc(o.action)}">${csrfField(o.csrf)}
<input type="email" name="username" autocomplete="username" value="${esc(o.email)}" hidden>
<label for="password">${esc(t.newPassword)}</label><input id="password" name="password" type="password" autocomplete="new-password" minlength="8" required autofocus>
<label for="confirm">${esc(t.confirmPassword)}</label><input id="confirm" name="confirm" type="password" autocomplete="new-password" minlength="8" required>
<button type="submit">${esc(t.setPassword)}</button></form>`;
}

export function message(o: { title: string; text: string; link?: { href: string; label: string }; error?: boolean }) {
  return `<h1>${esc(o.title)}</h1><p ${o.error ? 'class="err" role="alert"' : 'role="status"'}>${esc(o.text)}</p>${o.link ? `<a class="btn" href="${esc(o.link.href)}">${esc(o.link.label)}</a>` : ''}`;
}

export function accountPage(t: Strings, o: { base: string; csrf: string; email?: string; mfaEnabled?: boolean; mfaRequired: boolean; notice?: string; error?: string }) {
  const id = (k: string) => `${k}`;
  const creds = (prefix: string) => `<label for="${id(`${prefix}-email`)}">${esc(t.email)}</label><input id="${id(`${prefix}-email`)}" name="email" type="email" autocomplete="username" required value="${esc(o.email)}">
<label for="${id(`${prefix}-password`)}">${esc(t.currentPassword)}</label><input id="${id(`${prefix}-password`)}" name="password" type="password" autocomplete="current-password" required>`;
  return `<h1>${esc(t.accountTitle)}</h1><p class="muted">${esc(t.accountHelp)}</p>${errorLine(o.error)}${o.notice ? `<p role="status">${esc(o.notice)}</p>` : ''}
<section><h2>${esc(t.changePassword)}</h2><form method="post" action="${esc(o.base)}/password">${csrfField(o.csrf)}${creds('pw')}
<label for="pw-new">${esc(t.newPassword)}</label><input id="pw-new" name="newPassword" type="password" autocomplete="new-password" minlength="8" required>
<label for="pw-confirm">${esc(t.confirmPassword)}</label><input id="pw-confirm" name="confirm" type="password" autocomplete="new-password" minlength="8" required>
<button type="submit">${esc(t.changePassword)}</button></form></section>
<section><h2>${esc(t.mfaTitle)}</h2>
<form method="post" action="${esc(o.base)}/mfa/enable">${csrfField(o.csrf)}${creds('on')}<button type="submit">${esc(t.enableMfa)}</button></form></section>
<section><h2>${esc(t.disableMfa)}</h2>${o.mfaRequired ? `<p class="muted">${esc(t.mfaRequiredByRealm)}</p>` : ''}
<form method="post" action="${esc(o.base)}/mfa/disable">${csrfField(o.csrf)}${creds('off')}
<label for="off-code">${esc(t.code)}</label><input id="off-code" name="code" inputmode="numeric" autocomplete="one-time-code" required maxlength="6">
<button type="submit" class="secondary">${esc(t.disableMfa)}</button>
<button type="submit" class="secondary" formaction="${esc(o.base)}/mfa/recovery">${esc(t.newRecovery)}</button></form></section>`;
}

export function logoutForm(t: Strings, form: string) {
  // `form` is generated by oidc-provider (hidden fields only); the submit button is ours.
  return `<h1>${esc(t.logoutTitle)}</h1><p>${esc(t.logoutHelp)}</p>${form}
<button type="submit" form="op.logoutForm" name="logout" value="yes" autofocus>${esc(t.logout)}</button>
<button type="submit" form="op.logoutForm" class="secondary">${esc(t.cancel)}</button>`;
}
