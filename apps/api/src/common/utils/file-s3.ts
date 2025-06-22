import { FILE_STORAGE_PATH } from '@/common/constants';
import { SaveFileOptions } from '@/common/interfaces/file.interface';
import { AWS_BUCKET_NAME, s3 } from '@/common/utils/amazon-s3';
import { getExtensionFromMimeType } from '@/common/utils/file';
import { concatStr } from '@/common/utils/index';
import { DeleteObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { MemoryStorageFile } from '@blazity/nest-file-fastify';
import { basename, join } from 'path';

/**
 * Saves a file buffer to S3.
 */
export async function saveFileToS3(
  storageFile: MemoryStorageFile,
  options: SaveFileOptions = {},
): Promise<{ filename: string; filepath: string }> {
  const {
    fileName,
    prefix = '',
    suffix = '',
    path = '', // Optional full or partial path
    separator = '',
  } = options;

  const isPathFile = path.includes('.');
  const extension = getExtensionFromMimeType(storageFile.mimetype) || '';
  const safeFileName =
    concatStr([prefix, fileName ?? Date.now(), suffix], separator) + extension;

  const relativePath = isPathFile
    ? path.replace(/\\/g, '/')
    : join(path || '', safeFileName).replace(/\\/g, '/'); // default to just the safe filename if no path

  await s3.send(
    new PutObjectCommand({
      Bucket: AWS_BUCKET_NAME,
      Key: relativePath,
      Body: storageFile.buffer,
      ContentType: storageFile.mimetype,
      ChecksumAlgorithm: undefined, // disable checksum headers for Backblaze B2 compatibility
    }),
  );

  return {
    filename: basename(relativePath),
    filepath: relativePath,
  };
}

/**
 * Saves multiple files to S3.
 */
export async function saveFilesToS3(
  storageFiles: MemoryStorageFile[],
  options: SaveFileOptions = {},
): Promise<{ filename: string; filepath: string }[]> {
  const tasks = storageFiles.map((file, index) => {
    const fileOptions: SaveFileOptions = {
      ...options,
      fileName: options.fileName ? `${options.fileName}-${index}` : undefined,
    };
    return saveFileToS3(file, fileOptions);
  });

  return await Promise.all(tasks);
}

/**
 * Deletes a single file from S3.
 */
export async function deleteFileFromS3(relativePath: string): Promise<void> {
  const s3Key = join(FILE_STORAGE_PATH, relativePath).replace(/\\/g, '/');

  try {
    await s3.send(
      new DeleteObjectCommand({
        Bucket: AWS_BUCKET_NAME,
        Key: s3Key,
      }),
    );
  } catch (error) {
    if ((error as any).$metadata?.httpStatusCode !== 404) throw error;
  }
}

/**
 * Deletes multiple files from S3.
 */
export async function deleteFilesFromS3(paths: string[]): Promise<void> {
  await Promise.allSettled(paths.map((path) => deleteFileFromS3(path)));
}
