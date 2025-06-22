import { S3Client } from '@aws-sdk/client-s3';

export const AWS_BUCKET_NAME = 'profile-0003-typle';

export const s3 = new S3Client({
  region: 'us-east-1', // Backblaze uses standard AWS region names, so 'us-east-1' is safer than 'us-east-005'
  endpoint: 'https://s3.us-east-005.backblazeb2.com', // full URL including https
  forcePathStyle: true, // important for Backblaze B2
  credentials: {
    accessKeyId: '00583c3e2e749900000000001',
    secretAccessKey: '00583c3e2e749900000000001',
  },
});
