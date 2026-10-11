import { SESv2Client, SendEmailCommand } from '@aws-sdk/client-sesv2';

export interface Mail { to: string; subject: string; text: string }

export interface Mailer {
  /** false when no sender is configured: the caller shows or returns the link instead. */
  readonly enabled: boolean;
  send(mail: Mail): Promise<void>;
}

export class SesMailer implements Mailer {
  private client?: SESv2Client;
  constructor(private readonly from?: string) {}
  get enabled() { return !!this.from; }

  async send(mail: Mail) {
    if (!this.from) return;
    this.client ??= new SESv2Client({});
    await this.client.send(new SendEmailCommand({
      FromEmailAddress: this.from,
      Destination: { ToAddresses: [mail.to] },
      Content: { Simple: { Subject: { Data: mail.subject, Charset: 'UTF-8' }, Body: { Text: { Data: mail.text, Charset: 'UTF-8' } } } },
    }));
  }
}

/** Tests and local runs. */
export class MemoryMailer implements Mailer {
  readonly sent: Mail[] = [];
  readonly enabled = true;
  async send(mail: Mail) { this.sent.push(mail); }
}
