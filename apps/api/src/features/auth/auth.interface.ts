import { Session } from '@/features/auth/entities/session.entity';
import { User } from '@/features/users/entities/user.entity';

/**
 * @description Sign in response
 */
export interface MessageResponse {
  message: string;
}

/**
 * @description Sign in response
 */
export interface SignInResponse {
  message: string;
  data: Omit<User, 'password' | 'sessions' | 'generateUserInfo'>;
  tokens: {
    access_token: string;
    refresh_token: string;
  };
}

/**
 * @description Sessions response
 */
export interface SessionsResponse {
  data: Session[];
}

/**
 * @description Session response
 */
export interface SessionResponse {
  data: Session;
}

/**
 * @description Refresh token response
 */
export interface RefreshTokenResponse {
  message: string;
  access_token: string;
  refresh_token: string;
  access_token_refresh_time: string;
  session_token: string;
}

/**
 * @description Auth tokens interface
 */
export interface AuthTokensInterface {
  access_token: string;
  refresh_token: string;
}

/**
 * @description Login user interface
 */
export interface LoginUserInterface {
  data: User;
  tokens: {
    session_token: string;
    access_token: string;
    refresh_token: string;
    session_refresh_time: string;
  };
}

/**
 *  @description Refresh token interface
 */
export interface RefreshTokenInterface {
  access_token: string;
  refresh_token: string;
  access_token_refresh_time: string;
  session_token: string;
}

/**
 * @description Register user interface
 */
export interface RegisterUserInterface {
  data: User;
}
