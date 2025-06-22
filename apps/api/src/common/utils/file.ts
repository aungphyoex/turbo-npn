import { FILE_STORAGE_PATH } from '@/common/constants';
import { SaveFileOptions } from '@/common/interfaces/file.interface';
import { concatStr } from '@/common/utils/index';
import { MemoryStorageFile } from '@blazity/nest-file-fastify';
import { constants } from 'fs';
import { access, mkdir, unlink, writeFile } from 'fs/promises';
import { basename, dirname, join } from 'path';

/**
 * Ensures that a directory exists. If it does not exist, creates it recursively.
 *
 * @param {string} dir - Absolute directory path to check or create.
 * @returns {Promise<void>}
 */
async function ensureDirExists(dir: string): Promise<void> {
  try {
    await access(dir, constants.F_OK);
  } catch {
    await mkdir(dir, { recursive: true });
  }
}

/**
 * Saves a file buffer to disk under the `storage/public` folder.
 *
 * @param {MemoryStorageFile} storageFile - File object with `buffer` and `mimetype`.
 * @param {SaveFileOptions} [options] - Optional save options including fileName, prefix, suffix, and path.
 * @returns {Promise<{ filename: string; filepath: string }>} An object containing the actual filename and filepath relative to `storage/public`.
 */
export async function saveFile(
  storageFile: MemoryStorageFile,
  options: SaveFileOptions = {},
): Promise<{ filename: string; filepath: string }> {
  const {
    fileName,
    prefix = '',
    suffix = '',
    path = '',
    separator = '',
  } = options;

  const isPathFile = path.includes('.');
  const folder = isPathFile ? dirname(path) : path;

  const extension = getExtensionFromMimeType(storageFile.mimetype) || '';
  const safeFileName =
    concatStr([prefix, fileName ?? Date.now(), suffix], separator) + extension;
  const relativeFilePath = isPathFile ? path : join(folder, safeFileName);
  const filePath = join(FILE_STORAGE_PATH, relativeFilePath);
  const dir = dirname(filePath);

  await ensureDirExists(dir);
  await writeFile(filePath, storageFile.buffer);

  return {
    filename: basename(filePath),
    filepath: relativeFilePath,
  };
}

/**
 * Saves multiple files to storage.
 *
 * @param {MemoryStorageFile[]} storageFiles - Array of files to be saved.
 * @param {SaveFileOptions} [options] - Optional save options applied to each file.
 * @returns {Promise<{ filename: string; filepath: string }[]>} Promise resolving to an array of objects containing filenames and filepaths.
 */
export async function saveFiles(
  storageFiles: MemoryStorageFile[],
  options: SaveFileOptions = {},
): Promise<{ filename: string; filepath: string }[]> {
  const saveTasks = storageFiles.map((file, index) => {
    const fileOptions: SaveFileOptions = {
      ...options,
      fileName: options.fileName ? `${options.fileName}-${index}` : undefined,
    };
    return saveFile(file, fileOptions);
  });

  return await Promise.all(saveTasks);
}

/**
 * Deletes a file from the `storage/public` directory.
 *
 * @param {string} relativePath - The file path relative to `storage/public` (e.g. "uploads/img.png").
 * @throws {Error} If an error occurs other than file-not-found (`ENOENT`).
 */
export async function deleteFile(relativePath: string) {
  const filePath = join(FILE_STORAGE_PATH, relativePath);
  try {
    return await unlink(filePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw error;
  }
}

/**
 * Deletes multiple files from the `storage/public` directory.
 *
 * @param {string[]} relativePaths - Array of file paths relative to `storage/public` (e.g. ["uploads/img1.png", "uploads/img2.png"]).
 * @throws {Error} If an error occurs other than file-not-found (`ENOENT`) for any file.
 */
export async function deleteFiles(relativePaths: string[]) {
  const deletePromises = relativePaths.map((relativePath) => {
    const filePath = join(FILE_STORAGE_PATH, relativePath);
    return deleteFile(filePath);
  });

  return await Promise.allSettled(deletePromises);
}

/**
 * Converts a MIME type to its typical file extension.
 *
 * @param {string} mimeType - The MIME type of the file (e.g. "image/jpeg").
 * @returns {string} The corresponding file extension (e.g. ".jpg"), or empty string if unknown.
 */
export function getExtensionFromMimeType(mimeType: string): string {
  const map: Record<string, string> = {
    'image/jpeg': '.jpg',
    'image/png': '.png',
    'image/gif': '.gif',
    'image/webp': '.webp',
    'image/svg+xml': '.svg',
    'application/pdf': '.pdf',
    'application/zip': '.zip',
    'application/json': '.json',
    'text/plain': '.txt',
    'text/html': '.html',
    'video/mp4': '.mp4',
    'audio/mpeg': '.mp3',
    'audio/wav': '.wav',
  };

  return map[mimeType] || '';
}
