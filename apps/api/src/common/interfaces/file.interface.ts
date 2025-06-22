/**
 * Options for customizing how a file is saved to storage.
 *
 * @property {string} [fileName] - The custom file name to use for saving (e.g., "avatar.png").
 *   If not provided, a unique name will be auto-generated.
 * @property {string} [prefix] - Optional string to prepend to the file name (e.g., "img_").
 * @property {string} [suffix] - Optional string to append to the file name (e.g., "_v2").
 * @property {string} [path] - Folder path or full file path relative to `storage/public`.
 * @property {string} [separator] - Separator to use separate file name `prefix{separator}filename{separator}suffix
 *   If a file extension is included (e.g., "uploads/file.jpg"), the value is treated as a full path.
 */
export interface SaveFileOptions {
  fileName?: string;
  prefix?: string;
  suffix?: string;
  path?: string;
  separator?: string;
}
