import { Base } from '@/common/entities';
import { Column, Entity } from 'typeorm';

/**
 * Enum representing supported OTP token types.
 */
enum TokenTypes {
  EMAIL_VERIFICATION = 'EMAIL_VERIFICATION',
  EMAIL_CONFIRMATION = 'EMAIL_CONFIRMATION',
  PASSWORD_RESET = 'PASSWORD_RESET',
}

/**
 * Entity representing a One-Time Password (OTP) record.
 *
 * @property {string} otp - The OTP code.
 * @property {Date} expires - The expiration date and time of the OTP.
 * @property {string} type - The OTP token type (see TokenTypes).
 */
@Entity()
export class Otp extends Base {
  /**
   * The OTP code.
   * @type {string}
   */
  @Column({ type: 'varchar', nullable: false })
  otp: string;

  /**
   * The expiration date and time of the OTP.
   * @type {Date}
   */
  @Column({ type: 'timestamp', nullable: false })
  expires: Date;

  /**
   * The OTP token type.
   * @type {string}
   */
  @Column({ type: 'enum', enum: TokenTypes, nullable: false })
  type: string;
}
