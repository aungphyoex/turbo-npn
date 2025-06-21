import { Base } from '@/common/entities';
import { hashString } from '@/common/utils';
import { Session } from '@/features/auth/entities/session.entity';
import { Profile } from '@/features/users/entities/profile.entity';
import {
  BeforeInsert,
  Column,
  Entity,
  OneToMany,
  OneToOne,
  Relation,
} from 'typeorm';

/**
 * Entity representing a user account.
 *
 * @property {string} email - The user's email address.
 * @property {string} password - The user's hashed password.
 * @property {string} username - The user's username.
 * @property {boolean} isEmailVerified - Whether the user's email is verified.
 * @property {Date} emailVerifiedAt - The date and time when the email was verified.
 * @property {Relation<Session[]>} sessions - Sessions associated with the user.
 * @property {Relation<Profile>} profile - Profile associated with the user.
 */
@Entity()
export class User extends Base {
  /**
   * The user's email address.
   * @type {string}
   */
  @Column({ type: 'varchar', unique: true, nullable: false })
  email: string;

  /**
   * The user's hashed password.
   * @type {string}
   */
  @Column({ type: 'varchar', nullable: true })
  password: string;

  /**
   * The user's username.
   * @type {string}
   */
  @Column({ type: 'varchar', unique: true, nullable: false })
  username: string;

  /**
   * Whether the user's email is verified.
   * @type {boolean}
   */
  @Column({ type: 'boolean', nullable: true, default: false })
  isEmailVerified: boolean;

  /**
   * The date and time when the email was verified.
   * @type {Date}
   */
  @Column({ type: 'timestamp', nullable: true })
  emailVerifiedAt: Date;

  /**
   * Sessions associated with the user.
   * @type {Relation<Session[]>}
   */
  @OneToMany(() => Session, (session) => session.user, {
    cascade: true,
  })
  sessions: Relation<Session[]>;

  /**
   * Profile associated with the user.
   * @type {Relation<Profile>}
   */
  @OneToOne(() => Profile, (profile) => profile.user, {
    cascade: true,
  })
  profile: Relation<Profile>;

  /**
   * Generates username and hashes password before inserting a new user.
   *
   * @returns {Promise<void>}
   */
  @BeforeInsert()
  async generateUserInfo(): Promise<void> {
    if (!this.username) {
      this.username = this.email.split('@')[0];
    }
    if (this.password) {
      this.password = await hashString(this.password);
    }
  }
}
