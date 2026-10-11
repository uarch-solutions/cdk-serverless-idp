import { App, RemovalPolicy, Stack } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { describe, expect, it } from 'vitest';
import { ServerlessIdp } from '../src';

const build = (props: ConstructorParameters<typeof ServerlessIdp>[2] = {}) => {
  const app = new App({ context: { 'aws:cdk:bundling-stacks': [] } });
  const stack = new Stack(app, 'Idp', { env: { account: '111111111111', region: 'us-east-1' } });
  const idp = new ServerlessIdp(stack, 'Idp', props);
  return { stack, idp, t: Template.fromStack(stack) };
};

describe('ServerlessIdp', () => {
  const cert = (stack: Stack) => acm.Certificate.fromCertificateArn(stack, 'Cert', 'arn:aws:acm:us-east-1:111111111111:certificate/abc');
  const withDomain = () => {
    const app = new App({ context: { 'aws:cdk:bundling-stacks': [] } });
    const stack = new Stack(app, 'Idp', { env: { account: '111111111111', region: 'us-east-1' } });
    const idp = new ServerlessIdp(stack, 'Idp', { domainName: 'id.acme.test', certificate: cert(stack), mailFrom: 'Acme <no-reply@acme.test>' });
    return { stack, idp, t: Template.fromStack(stack) };
  };
  const { t, idp } = withDomain();

  it('one on-demand table with TTL, point-in-time recovery, two indexes; retained by default', () => {
    t.hasResourceProperties('AWS::DynamoDB::GlobalTable', {
      BillingMode: 'PAY_PER_REQUEST', TimeToLiveSpecification: { AttributeName: 'ttl', Enabled: true },
      GlobalSecondaryIndexes: [Match.objectLike({ IndexName: 'gsi1' }), Match.objectLike({ IndexName: 'gsi3' })],
      Replicas: [Match.objectLike({ PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true }, DeletionProtectionEnabled: true })],
    });
    t.hasResource('AWS::DynamoDB::GlobalTable', { DeletionPolicy: 'Retain' });
  });

  it('public function behind CloudFront (custom domain, HTTPS only, no cache), origin header, issuer from the domain', () => {
    t.hasResourceProperties('AWS::Lambda::Function', {
      Architectures: ['arm64'], MemorySize: 1024,
      Environment: { Variables: Match.objectLike({ ISSUER_BASE: 'https://id.acme.test', MAIL_FROM: 'Acme <no-reply@acme.test>', ORIGIN_VERIFY: Match.anyValue() }) },
    });
    t.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        Aliases: ['id.acme.test'],
        DefaultCacheBehavior: Match.objectLike({ ViewerProtocolPolicy: 'redirect-to-https', CachePolicyId: '4135ea2d-6df8-44a3-9df3-4b5a84be39ad' }),
        Origins: [Match.objectLike({ OriginCustomHeaders: [Match.objectLike({ HeaderName: 'x-origin-verify' })] })],
      }),
    });
    expect(idp.url).toBe('https://id.acme.test');
  });

  it('admin function is not public; bootstrap trigger; secret written only by admin', () => {
    t.resourceCountIs('AWS::Lambda::Url', 1);
    t.resourceCountIs('Custom::Trigger', 1);
    const policies = JSON.stringify(Object.values(t.findResources('AWS::IAM::Policy')));
    expect(policies).toContain('secretsmanager:PutSecretValue');
    const web = Object.entries(t.findResources('AWS::IAM::Policy')).filter(([k]) => k.startsWith('IdpWebServiceRole'));
    expect(JSON.stringify(web)).not.toContain('PutSecretValue');
  });

  it('without a custom domain the issuer comes from the CloudFront name; a domain needs a certificate', () => {
    const { t: plain } = build();
    const web = Object.values(plain.findResources('AWS::Lambda::Function')).find((f: any) => f.Properties.Environment?.Variables?.ORIGIN_VERIFY) as any;
    expect(web.Properties.Environment.Variables.ISSUER_BASE).toBeUndefined();
    expect(() => build({ domainName: 'id.x.test' })).toThrow(/certificate/);
  });

  it('grantAdmin and allowHook add invoke permissions', () => {
    const app = new App({ context: { 'aws:cdk:bundling-stacks': [] } });
    const stack = new Stack(app, 'S', { env: { account: '111111111111', region: 'us-east-1' } });
    const idp2 = new ServerlessIdp(stack, 'Idp', { removalPolicy: RemovalPolicy.DESTROY });
    const backend = new lambda.Function(stack, 'Backend', { runtime: lambda.Runtime.NODEJS_22_X, handler: 'i.h', code: lambda.Code.fromInline('x') });
    idp2.grantAdmin(backend);
    idp2.allowHook(backend);
    const tpl = Template.fromStack(stack);
    tpl.hasResourceProperties('AWS::IAM::Policy', { PolicyDocument: { Statement: Match.arrayWith([Match.objectLike({ Action: 'lambda:InvokeFunction' })]) } });
    tpl.hasResource('AWS::DynamoDB::GlobalTable', { DeletionPolicy: 'Delete' });
  });
});
