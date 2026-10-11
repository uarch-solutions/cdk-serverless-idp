import * as path from 'path';
import { CfnOutput, Duration, RemovalPolicy, Stack } from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as triggers from 'aws-cdk-lib/triggers';
import { Construct } from 'constructs';

export interface ServerlessIdpProps {
  /** Public host name of the provider (e.g. `id.example.com`). Without it, the distribution's `*.cloudfront.net` name is used. */
  readonly domainName?: string;
  /** ACM certificate for `domainName`, in us-east-1 (CloudFront). Required with `domainName`. */
  readonly certificate?: acm.ICertificate;
  /** Verified SES sender for password-reset and invite e-mails (e.g. `Acme <no-reply@acme.com>`). Without it, links are only returned by the admin API. */
  readonly mailFrom?: string;
  /** Name shown in authenticator apps and e-mails. @default 'Sign in' */
  readonly productName?: string;
  /** @default 365 */
  readonly auditRetentionDays?: number;
  /** Memory of the public function (argon2id uses 64 MiB per check). @default 1024 */
  readonly memorySize?: number;
  /** @default RemovalPolicy.RETAIN — the table holds every account. */
  readonly removalPolicy?: RemovalPolicy;
  /** @default logs.RetentionDays.ONE_MONTH */
  readonly logRetention?: logs.RetentionDays;
}

/**
 * Multi-tenant OpenID Connect provider that costs nothing while nobody signs in: one Lambda (behind CloudFront) runs
 * `oidc-provider` with a realm per customer, one DynamoDB on-demand table holds everything (TTL expires sessions and
 * tokens for free) and an IAM-only admin Lambda manages realms, applications and people.
 */
export class ServerlessIdp extends Construct {
  /** Base URL; each realm's issuer is `<url>/realms/<realm>`. */
  public readonly url: string;
  public readonly table: dynamodb.TableV2;
  public readonly webFunction: lambda.Function;
  /** Admin API (IAM only): grant `lambda:InvokeFunction` with `grantAdmin`. */
  public readonly adminFunction: lambda.Function;
  public readonly distribution: cloudfront.Distribution;
  /** Signing keys, cookie keys and the data key (written by the bootstrap; never output). */
  public readonly runtimeSecret: secretsmanager.Secret;

  constructor(scope: Construct, id: string, props: ServerlessIdpProps = {}) {
    super(scope, id);
    if (props.domainName && !props.certificate) throw new Error('certificate is required with domainName');
    const removalPolicy = props.removalPolicy ?? RemovalPolicy.RETAIN;
    const logRetention = props.logRetention ?? logs.RetentionDays.ONE_MONTH;

    this.table = new dynamodb.TableV2(this, 'Table', {
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billing: dynamodb.Billing.onDemand(),
      timeToLiveAttribute: 'ttl',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      deletionProtection: removalPolicy === RemovalPolicy.RETAIN,
      removalPolicy,
      globalSecondaryIndexes: [
        { indexName: 'gsi1', partitionKey: { name: 'gsi1pk', type: dynamodb.AttributeType.STRING }, sortKey: { name: 'gsi1sk', type: dynamodb.AttributeType.STRING } },
        { indexName: 'gsi3', partitionKey: { name: 'gsi3pk', type: dynamodb.AttributeType.STRING }, sortKey: { name: 'gsi3sk', type: dynamodb.AttributeType.STRING }, projectionType: dynamodb.ProjectionType.KEYS_ONLY },
      ],
    });

    this.runtimeSecret = new secretsmanager.Secret(this, 'RuntimeSecret', {
      description: 'cdk-serverless-idp: signing keys, cookie keys and data key (written by the bootstrap)',
      removalPolicy,
    });
    // Header CloudFront adds to every request; the function refuses requests without it (no direct Function URL use).
    const originSecret = new secretsmanager.Secret(this, 'OriginSecret', {
      description: 'cdk-serverless-idp: CloudFront → Lambda origin header',
      generateSecretString: { excludePunctuation: true, passwordLength: 48 },
    });
    const originVerify = originSecret.secretValue.unsafeUnwrap();

    const common = {
      runtime: lambda.Runtime.NODEJS_22_X,
      architecture: lambda.Architecture.ARM_64,
      handler: 'index.handler',
    };
    const env = {
      TABLE_NAME: this.table.tableName,
      SECRET_ID: this.runtimeSecret.secretArn,
      PRODUCT_NAME: props.productName ?? 'Sign in',
      AUDIT_RETENTION_DAYS: String(props.auditRetentionDays ?? 365),
      ...(props.mailFrom ? { MAIL_FROM: props.mailFrom } : {}),
    };

    this.webFunction = new lambda.Function(this, 'Web', {
      ...common,
      code: lambda.Code.fromAsset(path.join(__dirname, '..', 'dist', 'web')),
      memorySize: props.memorySize ?? 1024,
      timeout: Duration.seconds(15),
      description: 'cdk-serverless-idp: hosted pages and the OpenID Provider of every realm',
      logGroup: new logs.LogGroup(this, 'WebLogs', { retention: logRetention, removalPolicy: RemovalPolicy.DESTROY }),
      environment: {
        ...env,
        ORIGIN_VERIFY: originVerify,
        // Without a custom domain the issuer comes from the CloudFront host (a reference here would be circular).
        ...(props.domainName ? { ISSUER_BASE: `https://${props.domainName}` } : {}),
      },
    });
    const functionUrl = this.webFunction.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.NONE });

    // CloudFront forwards the viewer host (URLs are built from it); the Function URL already sets X-Forwarded-Proto.
    const forwardHost = new cloudfront.Function(this, 'ForwardHost', {
      runtime: cloudfront.FunctionRuntime.JS_2_0,
      comment: 'cdk-serverless-idp: X-Forwarded-Host',
      code: cloudfront.FunctionCode.fromInline(`function handler(event) {
  var r = event.request;
  r.headers['x-forwarded-host'] = { value: r.headers.host.value };
  return r;
}`),
    });
    this.distribution = new cloudfront.Distribution(this, 'Distribution', {
      comment: 'cdk-serverless-idp',
      ...(props.domainName ? { domainNames: [props.domainName], certificate: props.certificate } : {}),
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      defaultBehavior: {
        origin: new origins.FunctionUrlOrigin(functionUrl, { customHeaders: { 'x-origin-verify': originVerify } }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
        functionAssociations: [{ function: forwardHost, eventType: cloudfront.FunctionEventType.VIEWER_REQUEST }],
      },
    });
    this.url = `https://${props.domainName ?? this.distribution.distributionDomainName}`;

    this.adminFunction = new lambda.Function(this, 'Admin', {
      ...common,
      code: lambda.Code.fromAsset(path.join(__dirname, '..', 'dist', 'admin')),
      memorySize: 512,
      timeout: Duration.seconds(60),
      description: 'cdk-serverless-idp: admin API (IAM only) and bootstrap',
      logGroup: new logs.LogGroup(this, 'AdminLogs', { retention: logRetention, removalPolicy: RemovalPolicy.DESTROY }),
      // Without a custom domain, the admin reads the address the public function learned (no reference: no cycle).
      environment: { ...env, ...(props.domainName ? { ISSUER_BASE: this.url } : {}) },
    });

    this.table.grantReadWriteData(this.webFunction);
    this.table.grantReadWriteData(this.adminFunction);
    this.runtimeSecret.grantRead(this.webFunction);
    this.runtimeSecret.grantRead(this.adminFunction);
    this.runtimeSecret.grantWrite(this.adminFunction);
    if (props.mailFrom) {
      for (const fn of [this.webFunction, this.adminFunction]) {
        fn.addToRolePolicy(new iam.PolicyStatement({ actions: ['ses:SendEmail'], resources: ['*'] }));
      }
    }
    // Lambda post-login hooks: the application grants the web function permission to invoke its hook.

    // First deployment: create the signing keys, cookie keys and data key (idempotent).
    new triggers.Trigger(this, 'Bootstrap', { handler: this.adminFunction, executeAfter: [this.table, this.runtimeSecret], timeout: Duration.minutes(1) });

    new CfnOutput(this, 'Url', { value: this.url, description: 'Base URL; realm issuers are <url>/realms/<realm>' });
    new CfnOutput(this, 'DistributionDomainName', { value: this.distribution.distributionDomainName, description: 'CNAME target for the custom domain' });
    new CfnOutput(this, 'AdminFunctionName', { value: this.adminFunction.functionName, description: 'Invoke with IAM to manage realms, applications and people' });
  }

  /** Lets a principal (e.g. your application's backend) call the admin API. */
  grantAdmin(grantee: iam.IGrantable) {
    return this.adminFunction.grantInvoke(grantee);
  }

  /** Lets the provider invoke an application's Lambda post-login hook. */
  allowHook(hook: lambda.IFunction) {
    return hook.grantInvoke(this.webFunction);
  }

  /** Region of the stack (the admin API lives there). */
  get region() {
    return Stack.of(this).region;
  }
}
