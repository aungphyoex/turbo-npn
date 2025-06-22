import { join } from 'path';

/**
 * Base directory where files will be saved and deleted.
 * Uses the project root (not the compiled `dist` folder).
 */
export const FILE_STORAGE_PATH = join(process.cwd(), 'storage', 'public');
