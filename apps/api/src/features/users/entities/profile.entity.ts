import { Base } from '@/common/entities';
import { Column, Entity, JoinColumn, OneToOne, Relation } from 'typeorm';
import { User } from './user.entity';

/**
 * Enum representing possible genders for a profile.
 */
enum Gender {
  MALE = 'MALE',
  FEMALE = 'FEMALE',
  OTHER = 'OTHER',
  UNKNOWN = 'UNKNOWN',
}

/**
 * Entity representing a user's profile.
 *
 * @property {Relation<User>} user - The user associated with this profile.
 * @property {string} user_id - The user ID.
 * @property {string} name - The name of the user.
 * @property {string} gender - The gender of the user.
 * @property {string} [phoneNumber] - The phone number of the user.
 * @property {string} [profilePicture] - The profile picture URL or path.
 * @property {string} [dateOfBirth] - The date of birth of the user.
 * @property {string} [address] - The address of the user.
 */
@Entity()
export class Profile extends Base {
  /**
   * The user associated with this profile.
   * @type {Relation<User>}
   */
  @OneToOne(() => User, (user) => user.sessions, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id', referencedColumnName: 'id' })
  user: Relation<User>;

  /**
   * The user ID.
   * @type {string}
   */
  @Column({ type: 'uuid' })
  user_id: string;

  /**
   * The name of the user.
   * @type {string}
   */
  @Column({ nullable: false })
  name: string;

  /**
   * The gender of the user.
   * @type {string}
   */
  @Column({ type: 'enum', enum: Gender, default: Gender.UNKNOWN })
  gender: string;

  /**
   * The phone number of the user.
   * @type {string | undefined}
   */
  @Column({ unique: true, nullable: true })
  phoneNumber?: string;

  /**
   * The profile picture URL or path.
   * @type {string | undefined}
   */
  @Column({ nullable: true })
  profilePicture?: string;

  /**
   * The date of birth of the user.
   * @type {string | undefined}
   */
  @Column({ type: 'timestamp', nullable: true })
  dateOfBirth?: string;

  /**
   * The address of the user.
   * @type {string | undefined}
   */
  @Column({ nullable: true, type: 'text' })
  address?: string;
}
