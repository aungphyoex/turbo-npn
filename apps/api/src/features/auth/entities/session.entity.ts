import { Base } from '@/common/entities';
import { User } from '@/features/users/entities/user.entity';
import { Column, Entity, JoinColumn, ManyToOne, Relation } from 'typeorm';

/**
 * Entity representing a user session.
 *
 * @property {string} ip - IP address of the session.
 * @property {string} location - Geographical location of the session.
 * @property {string} device_os - Operating system of the device.
 * @property {string} device_name - Name of the device.
 * @property {string} device_type - Type of the device.
 * @property {string} browser - Browser used in the session.
 * @property {string} userAgent - User agent string of the session.
 * @property {string} refresh_token - Refresh token associated with the session.
 * @property {Relation<User>} user - User entity associated with the session.
 * @property {string} user_id - ID of the user associated with the session.
 */
@Entity()
export class Session extends Base {
  /**
   * IP address of the session.
   * @type {string}
   */
  @Column({ type: 'varchar', nullable: true, default: 'unknown' })
  ip: string;

  /**
   * Geographical location of the session.
   * @type {string}
   */
  @Column({ type: 'varchar', nullable: true, default: 'unknown' })
  location: string;

  /**
   * Operating system of the device.
   * @type {string}
   */
  @Column({ type: 'varchar', nullable: true, default: 'unknown' })
  device_os: string;

  /**
   * Name of the device.
   * @type {string}
   */
  @Column({ type: 'varchar', nullable: true, default: 'unknown' })
  device_name: string;

  /**
   * Type of the device.
   * @type {string}
   */
  @Column({ type: 'varchar', nullable: true, default: 'unknown' })
  device_type: string;

  /**
   * Browser used in the session.
   * @type {string}
   */
  @Column({ type: 'varchar', nullable: true, default: 'unknown' })
  browser: string;

  /**
   * User agent string of the session.
   * @type {string}
   */
  @Column({ type: 'varchar', nullable: true, default: 'unknown' })
  userAgent: string;

  /**
   * Refresh token associated with the session.
   * @type {string}
   */
  @Column({ type: 'text' })
  refresh_token: string;

  /**
   * User entity associated with the session.
   * @type {Relation<User>}
   */
  @ManyToOne(() => User, (user) => user.sessions, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id', referencedColumnName: 'id' })
  user: Relation<User>;

  /**
   * ID of the user associated with the session.
   * @type {string}
   */
  @Column({ type: 'uuid' })
  user_id: string;
}
