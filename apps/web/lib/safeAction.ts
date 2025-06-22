import { createSafeActionClient } from 'next-safe-action';

/**
 * Creates a safe action client for server actions with centralized error handling.
 *
 * @constant
 *
 * This client wraps server actions to provide safe error handling.
 * When an error occurs in any server action, it will be caught and logged to the console.
 * The error message will be returned as the result of the action to allow graceful handling on the client side.
 */
export const safeAction = createSafeActionClient({
  handleServerError(e) {
    console.error('Action error:', e.message);
    return e.message;
  },
});
