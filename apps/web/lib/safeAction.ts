import { createSafeActionClient } from 'next-safe-action';

export const safeAction = createSafeActionClient({
  handleServerError(e) {
    console.error('Action error:', e.message);
    return e.message;
  },
});
