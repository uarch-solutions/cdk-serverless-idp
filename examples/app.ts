import { App, Stack } from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { ServerlessIdp } from 'cdk-serverless-idp';

const app = new App();
const stack = new Stack(app, 'Identity', { env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION } });

const certificate = acm.Certificate.fromCertificateArn(stack, 'Cert', 'arn:aws:acm:us-east-1:123456789012:certificate/…'); // us-east-1 (CloudFront)
const idp = new ServerlessIdp(stack, 'Idp', {
  domainName: 'id.example.com',
  certificate,
  mailFrom: 'Example <no-reply@example.com>',
  productName: 'Example',
});

// Your backend: manages realms, applications and people through the admin API.
const backend = lambda.Function.fromFunctionName(stack, 'Backend', 'my-backend');
idp.grantAdmin(backend);
